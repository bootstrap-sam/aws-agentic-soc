# Internet-facing ALB in the two public subnets.
resource "aws_lb" "lab" {
  name               = "lab-alb"
  load_balancer_type = "application"
  internal           = false
  subnets            = aws_subnet.public[*].id
  security_groups    = [aws_security_group.alb.id]
}

# Target groups. "ip" targets register the containers by private IP.
resource "aws_lb_target_group" "all" {
  name        = "tg-all"
  port        = 80
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.lab.id

  health_check {
    path                = "/health"
    interval            = 10
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

resource "aws_lb_target_group" "a" {
  name        = "tg-app-a"
  port        = 80
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.lab.id
  health_check { path = "/health" }
}

resource "aws_lb_target_group" "b" {
  name        = "tg-app-b"
  port        = 80
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.lab.id
  health_check { path = "/health" }
}

locals {
  app_a_ip = "172.30.11.10"
  app_b_ip = "172.30.12.10"
}

resource "aws_lb_target_group_attachment" "all_a" {
  target_group_arn = aws_lb_target_group.all.arn
  target_id        = local.app_a_ip
}

resource "aws_lb_target_group_attachment" "all_b" {
  target_group_arn = aws_lb_target_group.all.arn
  target_id        = local.app_b_ip
}

resource "aws_lb_target_group_attachment" "a" {
  target_group_arn = aws_lb_target_group.a.arn
  target_id        = local.app_a_ip
}

resource "aws_lb_target_group_attachment" "b" {
  target_group_arn = aws_lb_target_group.b.arn
  target_id        = local.app_b_ip
}

# Listener: anything not matched by a rule round-robins across both apps.
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.lab.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.all.arn
  }
}

# Rules are evaluated lowest priority number first; first match wins.
resource "aws_lb_listener_rule" "path_a" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 10
  condition {
    path_pattern { values = ["/a", "/a/*"] }
  }
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.a.arn
  }
}

resource "aws_lb_listener_rule" "path_b" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 20
  condition {
    path_pattern { values = ["/b", "/b/*"] }
  }
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.b.arn
  }
}

resource "aws_lb_listener_rule" "beta_header" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 5
  condition {
    http_header {
      http_header_name = "X-Beta"
      values           = ["true"]
    }
  }
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.b.arn
  }
}

resource "aws_lb_listener_rule" "maintenance" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 40
  condition {
    path_pattern { values = ["/maintenance"] }
  }
  action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Down for maintenance (fixed response from the ALB itself)\n"
      status_code  = "503"
    }
  }
}

resource "aws_lb_listener_rule" "old_docs" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 50
  condition {
    path_pattern { values = ["/old-docs*"] }
  }
  action {
    type = "redirect"
    redirect {
      path        = "/b/docs"
      status_code = "HTTP_301"
    }
  }
}
