output "vpc_id" { value = aws_vpc.lab.id }
output "alb_dns_name" { value = aws_lb.lab.dns_name }
output "web_acl_arn" { value = aws_wafv2_web_acl.lab.arn }
output "front_door" { value = "http://localhost:8080  (WAF -> ALB)" }
output "alb_direct" { value = "http://localhost:8081  (ALB only, bypasses WAF)" }
