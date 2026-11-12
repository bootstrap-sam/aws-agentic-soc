# A classic two-tier VPC: public subnets for the ALB, private subnets for apps.
#
#   172.30.0.0/16  lab-vpc
#   ├── 172.30.1.0/24   public-a   (us-east-1a)  ─┐ route 0.0.0.0/0 → IGW
#   ├── 172.30.2.0/24   public-b   (us-east-1b)  ─┘
#   ├── 172.30.11.0/24  private-a  (us-east-1a)  ─┐ route 0.0.0.0/0 → NAT GW
#   └── 172.30.12.0/24  private-b  (us-east-1b)  ─┘
#
# The CIDR matches the Docker network in docker-compose.yml, so app-a
# (172.30.11.10) and app-b (172.30.12.10) really "live" in the private subnets.

resource "aws_vpc" "lab" {
  cidr_block           = "172.30.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "lab-vpc" }
}

locals {
  azs = ["us-east-1a", "us-east-1b"]
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "172.30.${count.index + 1}.0/24"
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = true
  tags                    = { Name = "public-${substr(local.azs[count.index], -1, 1)}", Tier = "public" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.lab.id
  cidr_block        = "172.30.${count.index + 11}.0/24"
  availability_zone = local.azs[count.index]
  tags              = { Name = "private-${substr(local.azs[count.index], -1, 1)}", Tier = "private" }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "lab-igw" }
}

# Private subnets reach the internet outbound-only via a NAT gateway,
# which itself sits in a public subnet with an Elastic IP.
resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "lab-nat-eip" }
}

resource "aws_nat_gateway" "lab" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  tags          = { Name = "lab-nat" }
  depends_on    = [aws_internet_gateway.lab]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }
  tags = { Name = "public-rt" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.lab.id
  }
  tags = { Name = "private-rt" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Security groups chain: internet → ALB SG (80) → App SG (80, only from ALB SG).
resource "aws_security_group" "alb" {
  name        = "alb-sg"
  description = "Public HTTP into the ALB"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "app" {
  name        = "app-sg"
  description = "Apps accept traffic only from the ALB"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description     = "HTTP from ALB only"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
