#!/usr/bin/env bash
# Rebuilds the Phase 2 infrastructure with the AWS CLI. This is the scripted
# equivalent of docs/phases/phase-2-network-and-compute.md.
#
# Run from AWS CloudShell (signed in as LabAdmin) in the repo root:
#   bash infra/build-phase2.sh
#
# Creates: VPC, public subnet, internet gateway, route table, security group
# (NO inbound rules; outbound 80/443), SSM-only instance role, t4g.micro
# instance (IMDSv2, encrypted gp3, standard credits, no key pair), Elastic IP.
# It doesn't touch the LabOperator permission set (Identity Center, done in the console).
set -euo pipefail

export AWS_REGION="${AWS_REGION:-us-east-1}"
NAME=honeypot
TAG="{Key=Project,Value=${NAME}}"
VPC_CIDR=10.20.0.0/16
SUBNET_CIDR=10.20.0.0/24
AZ="${AWS_REGION}a"
ROLE=honeypot-ec2-ssm-role
HERE="$(cd "$(dirname "$0")" && pwd)"

tags() { # tags <resource-type> <name>
  echo "ResourceType=$1,Tags=[{Key=Name,Value=$2},${TAG}]"
}

echo "==> VPC"
VPC_ID=$(aws ec2 create-vpc --cidr-block "$VPC_CIDR" \
  --tag-specifications "$(tags vpc ${NAME}-vpc)" \
  --query Vpc.VpcId --output text)
aws ec2 modify-vpc-attribute --vpc-id "$VPC_ID" --enable-dns-support '{"Value":true}'
aws ec2 modify-vpc-attribute --vpc-id "$VPC_ID" --enable-dns-hostnames '{"Value":true}'

echo "==> Internet gateway"
IGW_ID=$(aws ec2 create-internet-gateway \
  --tag-specifications "$(tags internet-gateway ${NAME}-igw)" \
  --query InternetGateway.InternetGatewayId --output text)
aws ec2 attach-internet-gateway --internet-gateway-id "$IGW_ID" --vpc-id "$VPC_ID"

echo "==> Public subnet + route table"
SUBNET_ID=$(aws ec2 create-subnet --vpc-id "$VPC_ID" --cidr-block "$SUBNET_CIDR" \
  --availability-zone "$AZ" \
  --tag-specifications "$(tags subnet ${NAME}-public)" \
  --query Subnet.SubnetId --output text)
RTB_ID=$(aws ec2 create-route-table --vpc-id "$VPC_ID" \
  --tag-specifications "$(tags route-table ${NAME}-public-rt)" \
  --query RouteTable.RouteTableId --output text)
aws ec2 create-route --route-table-id "$RTB_ID" \
  --destination-cidr-block 0.0.0.0/0 --gateway-id "$IGW_ID" >/dev/null
aws ec2 associate-route-table --route-table-id "$RTB_ID" --subnet-id "$SUBNET_ID" >/dev/null

echo "==> Security group (no inbound; outbound 80/443 only)"
SG_ID=$(aws ec2 create-security-group --vpc-id "$VPC_ID" \
  --group-name ${NAME}-sg --description "Honeypot - inbound added in Phase 3" \
  --tag-specifications "$(tags security-group ${NAME}-sg)" \
  --query GroupId --output text)
aws ec2 revoke-security-group-egress --group-id "$SG_ID" \
  --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]' >/dev/null
aws ec2 authorize-security-group-egress --group-id "$SG_ID" --ip-permissions '[
  {"IpProtocol":"tcp","FromPort":443,"ToPort":443,"IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"SSM, log shipping, APIs"}]},
  {"IpProtocol":"tcp","FromPort":80,"ToPort":80,"IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"Ubuntu apt mirrors"}]}
]' >/dev/null

echo "==> IAM role + instance profile (SSM only)"
aws iam create-role --role-name "$ROLE" \
  --assume-role-policy-document "file://${HERE}/ec2-trust-policy.json" \
  --tags Key=Project,Value=${NAME} >/dev/null
aws iam attach-role-policy --role-name "$ROLE" \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
aws iam create-instance-profile --instance-profile-name "$ROLE" >/dev/null
aws iam add-role-to-instance-profile --instance-profile-name "$ROLE" --role-name "$ROLE"
echo "    waiting 15s for IAM to propagate..."
sleep 15

echo "==> Instance"
AMI_ID=$(aws ssm get-parameter \
  --name /aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id \
  --query Parameter.Value --output text)
INSTANCE_ID=$(aws ec2 run-instances \
  --image-id "$AMI_ID" --instance-type t4g.micro \
  --subnet-id "$SUBNET_ID" --security-group-ids "$SG_ID" \
  --associate-public-ip-address \
  --iam-instance-profile Name="$ROLE" \
  --metadata-options HttpEndpoint=enabled,HttpTokens=required,HttpPutResponseHopLimit=1,InstanceMetadataTags=disabled \
  --credit-specification CpuCredits=standard \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":20,"VolumeType":"gp3","Encrypted":true,"DeleteOnTermination":true}}]' \
  --user-data "file://${HERE}/user-data.sh" \
  --tag-specifications "$(tags instance ${NAME}-01)" "$(tags volume ${NAME}-01-root)" "$(tags network-interface ${NAME}-01-eni)" \
  --query 'Instances[0].InstanceId' --output text)
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID"

echo "==> Elastic IP"
ALLOC_ID=$(aws ec2 allocate-address --domain vpc \
  --tag-specifications "$(tags elastic-ip ${NAME}-eip)" \
  --query AllocationId --output text)
aws ec2 associate-address --instance-id "$INSTANCE_ID" --allocation-id "$ALLOC_ID" >/dev/null
EIP=$(aws ec2 describe-addresses --allocation-ids "$ALLOC_ID" --query 'Addresses[0].PublicIp' --output text)

cat <<SUMMARY

Done.
  VPC:        $VPC_ID
  Subnet:     $SUBNET_ID
  SG:         $SG_ID   (no inbound rules)
  Instance:   $INSTANCE_ID
  Elastic IP: $EIP

Next: wait ~5 min, then connect with Session Manager and run the Step 7 checks.
SUMMARY
