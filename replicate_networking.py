import argparse
import json
import sys
from typing import Dict, List

import boto3
from botocore.exceptions import ClientError


def get_all(paginator, result_key: str, **kwargs) -> List[dict]:
    """Generic paginator helper."""
    items = []
    for page in paginator.paginate(**kwargs):
        items.extend(page.get(result_key, []))
    return items


# ---------- Security Groups ----------

def fetch_sg_maps(prod_ec2, dr_ec2, prod_vpc_id: str, dr_vpc_id: str):
    """Fetch SGs from Prod and DR for the specified VPCs, build name-based maps."""
    prod_sgs = prod_ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [prod_vpc_id]}]
    )["SecurityGroups"]

    dr_sgs = dr_ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [dr_vpc_id]}]
    )["SecurityGroups"]

    # Filter out default
    filtered_prod_sgs = [sg for sg in prod_sgs if sg["GroupName"] != "default"]

    # Map by name
    prod_by_name = {sg["GroupName"]: sg for sg in filtered_prod_sgs}
    dr_by_name = {sg["GroupName"]: sg for sg in dr_sgs}

    return prod_by_name, dr_by_name


def translate_permissions(ip_permissions: List[dict],
                          sg_id_map: Dict[str, str]) -> List[dict]:
    """
    Translate UserIdGroupPairs GroupId from Prod to DR using mapping.
    If a referenced SG doesn't exist in DR, that pair is skipped.
    """
    translated = []

    for perm in ip_permissions:
        new_perm = perm.copy()
        user_pairs = perm.get("UserIdGroupPairs", [])
        new_pairs = []

        for pair in user_pairs:
            prod_id = pair.get("GroupId")
            if prod_id and prod_id in sg_id_map:
                new_pair = pair.copy()
                new_pair["GroupId"] = sg_id_map[prod_id]
                new_pairs.append(new_pair)
            else:
                # If we can't map the SG, skip that pair
                print(f"      [SG] WARNING: skipping rule referencing SG {prod_id}")

        new_perm["UserIdGroupPairs"] = new_pairs
        translated.append(new_perm)

    return translated


def ensure_sgs_in_dr(prod_ec2, dr_ec2, prod_vpc_id: str, dr_vpc_id: str,
                     dry_run: bool) -> Dict[str, str]:
    """
    Ensure all non-default Prod SGs in the given VPC exist in DR VPC.
    Returns mapping: prod_sg_id -> dr_sg_id
    """
    prod_by_name, dr_by_name = fetch_sg_maps(
        prod_ec2, dr_ec2, prod_vpc_id, dr_vpc_id
    )

    sg_id_map: Dict[str, str] = {}

    # First pass: create missing SGs (without rules)
    for name, prod_sg in prod_by_name.items():
        if name in dr_by_name:
            dr_sg = dr_by_name[name]
            sg_id_map[prod_sg["GroupId"]] = dr_sg["GroupId"]
            print(f"[SG] Exists in DR: {name} ({dr_sg['GroupId']})")
            continue

        print(f"[SG] Creating in DR: {name}")
        if dry_run:
            print("      (dry-run, not creating)")
            continue

        kwargs = {
            "GroupName": name,
            "Description": prod_sg["Description"],
            "VpcId": dr_vpc_id,
        }

        tags = prod_sg.get("Tags")
        if tags:
            kwargs["TagSpecifications"] = [{
                "ResourceType": "security-group",
                "Tags": tags,
            }]

        resp = dr_ec2.create_security_group(**kwargs)
        new_id = resp["GroupId"]
        sg_id_map[prod_sg["GroupId"]] = new_id

    # Refresh DR SGs for mapping (covers existing + newly created)
    if not dry_run:
        dr_sgs = dr_ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [dr_vpc_id]}]
        )["SecurityGroups"]
        dr_by_name = {sg["GroupName"]: sg for sg in dr_sgs}
        for name, prod_sg in prod_by_name.items():
            if name in dr_by_name:
                sg_id_map[prod_sg["GroupId"]] = dr_by_name[name]["GroupId"]

    # Second pass: copy rules (ingress + egress)
    for name, prod_sg in prod_by_name.items():
        prod_id = prod_sg["GroupId"]
        if prod_id not in sg_id_map:
            print(f"[SG] WARNING: No DR SG id for {name}, skipping rules.")
            continue

        dr_id = sg_id_map[prod_id]
        print(f"[SG] Syncing rules for {name} ({prod_id} -> {dr_id})")

        ingress = translate_permissions(prod_sg.get("IpPermissions", []), sg_id_map)
        egress = translate_permissions(prod_sg.get("IpPermissionsEgress", []), sg_id_map)

        if dry_run:
            print("      (dry-run, not authorizing rules)")
            continue

        # Ingress
        if ingress:
            try:
                dr_ec2.authorize_security_group_ingress(
                    GroupId=dr_id,
                    IpPermissions=ingress
                )
            except ClientError as e:
                if e.response["Error"]["Code"] != "InvalidPermission.Duplicate":
                    print(f"[SG] ERROR ingress {name}: {e}")
        # Egress
        if egress:
            try:
                dr_ec2.authorize_security_group_egress(
                    GroupId=dr_id,
                    IpPermissions=egress
                )
            except ClientError as e:
                if e.response["Error"]["Code"] != "InvalidPermission.Duplicate":
                    print(f"[SG] ERROR egress {name}: {e}")

    return sg_id_map


# ---------- Target Groups ----------

def ensure_target_groups_in_dr(prod_elb, dr_elb,
                               dr_vpc_id: str,
                               dry_run: bool) -> Dict[str, str]:
    """
    Ensure all Prod target groups exist in DR VPC.
    Returns mapping: prod_tg_arn -> dr_tg_arn
    """
    paginator = prod_elb.get_paginator("describe_target_groups")
    prod_tgs = get_all(paginator, "TargetGroups")

    # DR: map by name
    try:
        dr_tgs = dr_elb.describe_target_groups()["TargetGroups"]
        dr_tg_map = {tg["TargetGroupName"]: tg for tg in dr_tgs}
    except ClientError as e:
        if e.response["Error"]["Code"] != "TargetGroupNotFound":
            raise
        dr_tg_map = {}

    tg_arn_map: Dict[str, str] = {}

    for tg in prod_tgs:
        name = tg["TargetGroupName"]
        prod_arn = tg["TargetGroupArn"]

        if name in dr_tg_map:
            dr_arn = dr_tg_map[name]["TargetGroupArn"]
            tg_arn_map[prod_arn] = dr_arn
            print(f"[TG] Exists in DR: {name}")
            continue

        print(f"[TG] Creating in DR: {name}")
        if dry_run:
            print("     (dry-run, not creating TG)")
            continue

        params = {
            "Name": name,
            "Protocol": tg["Protocol"],
            "Port": tg["Port"],
            "VpcId": dr_vpc_id,
            "HealthCheckProtocol": tg["HealthCheckProtocol"],
            "HealthCheckPort": tg["HealthCheckPort"],
            "HealthCheckEnabled": tg.get("HealthCheckEnabled", True),
            "HealthCheckIntervalSeconds": tg.get("HealthCheckIntervalSeconds", 30),
            "HealthCheckTimeoutSeconds": tg.get("HealthCheckTimeoutSeconds", 5),
            "HealthyThresholdCount": tg.get("HealthyThresholdCount", 5),
            "UnhealthyThresholdCount": tg.get("UnhealthyThresholdCount", 2),
            "TargetType": tg["TargetType"]
        }

        if "HealthCheckPath" in tg:
            params["HealthCheckPath"] = tg["HealthCheckPath"]

        resp = dr_elb.create_target_group(**params)
        new_tg = resp["TargetGroups"][0]
        dr_tg_map[name] = new_tg
        tg_arn_map[prod_arn] = new_tg["TargetGroupArn"]

    return tg_arn_map


# ---------- Load Balancers & Listeners ----------

def translate_actions(actions: List[dict], tg_arn_map: Dict[str, str]) -> List[dict]:
    """
    Translate actions (e.g., forward actions) from Prod TG ARNs to DR TG ARNs.
    Currently handles simple 'forward' actions.
    """
    new_actions = []
    for act in actions:
        new_act = act.copy()
        if act["Type"] == "forward":
            if "TargetGroupArn" in act:
                prod_arn = act["TargetGroupArn"]
                if prod_arn in tg_arn_map:
                    new_act["TargetGroupArn"] = tg_arn_map[prod_arn]
                else:
                    print(f"         WARNING: No TG mapping for {prod_arn}, action may break")
        new_actions.append(new_act)
    return new_actions


def ensure_lbs_in_dr(prod_elb, dr_elb,
                     vpc_map: dict,
                     sg_id_map: Dict[str, str],
                     tg_arn_map: Dict[str, str],
                     dry_run: bool):
    """Replicate LBs and listeners from Prod to DR based on VPC & subnet mapping."""
    paginator = prod_elb.get_paginator("describe_load_balancers")
    prod_lbs = get_all(paginator, "LoadBalancers")

    # DR LB map by name
    try:
        dr_lbs = dr_elb.describe_load_balancers()["LoadBalancers"]
        dr_by_name = {lb["LoadBalancerName"]: lb for lb in dr_lbs}
    except ClientError as e:
        if e.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise
        dr_by_name = {}

    lb_arn_map: Dict[str, str] = {}

    subnet_map: Dict[str, str] = vpc_map.get("subnet_map", {})

    # Create or reuse DR LBs
    for lb in prod_lbs:
        name = lb["LoadBalancerName"]
        prod_arn = lb["LoadBalancerArn"]
        print(f"[LB] Processing {name}")

        if name in dr_by_name:
            dr_arn = dr_by_name[name]["LoadBalancerArn"]
            lb_arn_map[prod_arn] = dr_arn
            print(f"     Exists in DR: {dr_arn}")
            continue

        # Map subnets
        prod_subnets = [az["SubnetId"] for az in lb["AvailabilityZones"]]
        dr_subnets = []
        for s in prod_subnets:
            if s not in subnet_map:
                print(f"     WARNING: no DR subnet mapping for {s}, skipping LB {name}")
                dr_subnets = []
                break
            dr_subnets.append(subnet_map[s])

        if not dr_subnets:
            continue

        # Map SGs (for ALB)
        dr_sg_ids = []
        for prod_sg_id in lb.get("SecurityGroups", []):
            if prod_sg_id not in sg_id_map:
                print(f"     WARNING: no SG mapping for {prod_sg_id}, skipping LB {name}")
                dr_sg_ids = []
                break
            dr_sg_ids.append(sg_id_map[prod_sg_id])

        if lb["Type"] == "application" and not dr_sg_ids:
            print(f"     ERROR: ALB {name} requires SGs, cannot create.")
            continue

        if dry_run:
            print("     (dry-run, not creating LB)")
            continue

        params = {
            "Name": name,
            "Subnets": dr_subnets,
            "Scheme": lb["Scheme"],
            "Type": lb["Type"],
            "IpAddressType": lb.get("IpAddressType", "ipv4"),
        }

        if dr_sg_ids:
            params["SecurityGroups"] = dr_sg_ids

        resp = dr_elb.create_load_balancer(**params)
        new_lb = resp["LoadBalancers"][0]
        dr_by_name[name] = new_lb
        lb_arn_map[prod_arn] = new_lb["LoadBalancerArn"]
        print(f"     Created DR LB: {new_lb['LoadBalancerArn']}")

    # Copy listeners for each LB we have an ARN mapping for
    for prod_arn, dr_arn in lb_arn_map.items():
        print(f"[LB] Syncing listeners {prod_arn} -> {dr_arn}")

        try:
            prod_listeners = prod_elb.describe_listeners(
                LoadBalancerArn=prod_arn
            )["Listeners"]
        except ClientError as e:
            print(f"     ERROR describing listeners for {prod_arn}: {e}")
            continue

        for listener in prod_listeners:
            print(f"     Listener {listener['Port']}/{listener['Protocol']}")
            # For simplicity, assume listener doesn't already exist in DR.
            if dry_run:
                print("         (dry-run, not creating listener)")
                continue

            # Translate default actions (only 'forward' TG case is handled fully here)
            default_actions = translate_actions(listener["DefaultActions"], tg_arn_map)

            params = {
                "LoadBalancerArn": dr_arn,
                "Protocol": listener["Protocol"],
                "Port": listener["Port"],
                "DefaultActions": default_actions
            }

            if "SslPolicy" in listener:
                params["SslPolicy"] = listener["SslPolicy"]
            if "Certificates" in listener:
                params["Certificates"] = listener["Certificates"]

            try:
                dr_elb.create_listener(**params)
            except ClientError as e:
                if e.response["Error"]["Code"] == "DuplicateListener":
                    print("         Listener already exists in DR, skipping.")
                else:
                    print(f"         ERROR creating listener: {e}")


# ---------- Main ----------

def main():
    parser = argparse.ArgumentParser(
        description="Replicate SecurityGroups, TargetGroups, and LoadBalancers from Prod to DR."
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to config.json"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not create or modify any resources in DR"
    )
    args = parser.parse_args()

    with open(args.config) as f:
        cfg = json.load(f)

    region   = cfg["region"]
    vpc_map  = cfg["vpc_map"]

    prod_profile = cfg["prod_profile"]
    dr_profile   = cfg["dr_profile"]

    # --- Create sessions using your CLI/SSO profiles ---
    print(f"Using AWS profile for Prod (READ-ONLY in script): {prod_profile}")
    prod_sess = boto3.Session(profile_name=prod_profile)

    print(f"Using AWS profile for DR (CREATE/MODIFY): {dr_profile}")
    dr_sess = boto3.Session(profile_name=dr_profile)

    # --- Extra safety: verify different accounts ---
    prod_sts = prod_sess.client("sts")
    dr_sts   = dr_sess.client("sts")

    prod_acct = prod_sts.get_caller_identity()["Account"]
    dr_acct   = dr_sts.get_caller_identity()["Account"]

    print(f"Prod account: {prod_acct}")
    print(f"DR account:   {dr_acct}")

    if prod_acct == dr_acct:
        raise RuntimeError("Prod and DR sessions are pointing to the SAME account. Aborting.")

    # --- Create service clients ---
    prod_ec2 = prod_sess.client("ec2", region_name=region)
    prod_elb = prod_sess.client("elbv2", region_name=region)

    dr_ec2   = dr_sess.client("ec2", region_name=region)
    dr_elb   = dr_sess.client("elbv2", region_name=region)

    prod_vpc_id = vpc_map["prod_vpc_id"]
    dr_vpc_id   = vpc_map["dr_vpc_id"]

    print("\n=== Step 1: Security Groups ===")
    sg_id_map = ensure_sgs_in_dr(
        prod_ec2,   # describe-only in this script
        dr_ec2,     # create/authorize in DR
        prod_vpc_id,
        dr_vpc_id,
        dry_run=args.dry_run
    )

    print("\n=== Step 2: Target Groups ===")
    tg_arn_map = ensure_target_groups_in_dr(
        prod_elb,   # describe-only
        dr_elb,     # create in DR
        dr_vpc_id,
        dry_run=args.dry_run
    )

    print("\n=== Step 3: Load Balancers + Listeners ===")
    ensure_lbs_in_dr(
        prod_elb,   # describe-only
        dr_elb,     # create in DR
        vpc_map,
        sg_id_map,
        tg_arn_map,
        dry_run=args.dry_run
    )

    print("\nDone.")


if __name__ == "__main__":
    sys.exit(main())
