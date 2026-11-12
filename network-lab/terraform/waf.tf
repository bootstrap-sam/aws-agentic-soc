# WAFv2 web ACL attached to the ALB. Floci stores it; the waf-enforcer
# container reads it back and applies it to traffic on localhost:8080.
#
# Rules run in priority order. Allow/Block stop evaluation; Count records a
# match (and adds labels) and carries on to the next rule.

resource "aws_wafv2_ip_set" "blocklist" {
  name               = "blocklist"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = ["203.0.113.0/24"] # TEST-NET-3
}

resource "aws_wafv2_ip_set" "office" {
  name               = "office"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = ["198.51.100.7/32"] # TEST-NET-2
}

resource "aws_wafv2_regex_pattern_set" "scanners" {
  name  = "scanner-user-agents"
  scope = "REGIONAL"
  regular_expression { regex_string = "(?i)(sqlmap|nikto|nmap|masscan)" }
}

resource "aws_wafv2_web_acl" "lab" {
  name  = "lab-web-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  custom_response_body {
    key          = "blocked-json"
    content_type = "APPLICATION_JSON"
    content      = jsonencode({ error = "blocked by WAF", hint = "check x-lab-waf-rule" })
  }

  # 1. Known-bad IPs are blocked outright.
  rule {
    name     = "block-ip-blocklist"
    priority = 10
    action {
      block {}
    }
    statement {
      ip_set_reference_statement { arn = aws_wafv2_ip_set.blocklist.arn }
    }
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "block-ip-blocklist"
    }
  }

  # 2. Scanner user agents: Count + label (doesn't block by itself).
  rule {
    name     = "label-scanners"
    priority = 20
    action {
      count {}
    }
    rule_label { name = "scanner" }
    statement {
      regex_pattern_set_reference_statement {
        arn = aws_wafv2_regex_pattern_set.scanners.arn
        field_to_match {
          single_header { name = "user-agent" }
        }
        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "label-scanners"
    }
  }

  # 3. SQL injection in the query string → block with a custom JSON body.
  rule {
    name     = "block-sqli-query"
    priority = 30
    action {
      block {
        custom_response {
          response_code            = 403
          custom_response_body_key = "blocked-json"
        }
      }
    }
    statement {
      sqli_match_statement {
        field_to_match {
          query_string {}
        }
        text_transformation {
          priority = 0
          type     = "URL_DECODE"
        }
        text_transformation {
          priority = 1
          type     = "LOWERCASE"
        }
      }
    }
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "block-sqli-query"
    }
  }

  # 4. /admin is only reachable from the office IP (AND + NOT).
  rule {
    name     = "admin-office-only"
    priority = 40
    action {
      block {}
    }
    statement {
      and_statement {
        statement {
          byte_match_statement {
            search_string         = "/admin"
            positional_constraint = "STARTS_WITH"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
        statement {
          not_statement {
            statement {
              ip_set_reference_statement { arn = aws_wafv2_ip_set.office.arn }
            }
          }
        }
      }
    }
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "admin-office-only"
    }
  }

  # 5. Block anything labelled "scanner" that also targets /admin or /b.
  rule {
    name     = "block-scanners-on-sensitive-paths"
    priority = 50
    action {
      block {}
    }
    statement {
      and_statement {
        statement {
          label_match_statement {
            scope = "LABEL"
            key   = "awswaf:000000000000:webacl:lab-web-acl:scanner"
          }
        }
        statement {
          regex_match_statement {
            regex_string = "^/(admin|b)"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }
      }
    }
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "block-scanners-on-sensitive-paths"
    }
  }

  # 6. Geo block (enforcer reads country from the X-Lab-Country header).
  rule {
    name     = "geo-block"
    priority = 60
    action {
      block {}
    }
    statement {
      geo_match_statement { country_codes = ["KP", "IR"] }
    }
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "geo-block"
    }
  }

  # 7. Rate limit /login: more than 10 requests per IP in 60s → blocked.
  #    The scope-down statement means only /login requests are counted.
  rule {
    name     = "rate-limit-login"
    priority = 70
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit                 = 10
        evaluation_window_sec = 60
        aggregate_key_type    = "IP"
        scope_down_statement {
          byte_match_statement {
            search_string         = "/login"
            positional_constraint = "STARTS_WITH"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }
      }
    }
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit-login"
    }
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "lab-web-acl"
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.lab.arn
  web_acl_arn  = aws_wafv2_web_acl.lab.arn
}
