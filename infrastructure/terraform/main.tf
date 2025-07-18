terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  # Use service account key file for authentication
  # credentials = file("path/to/service-account-key.json")
}


# VPC ネットワーク
resource "google_compute_network" "glen_network" {
  name                    = "glen-network"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "glen_subnet" {
  name          = "glen-subnet"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = google_compute_network.glen_network.id
}

# Enable required APIs
resource "google_project_service" "sqladmin" {
  project = var.project_id
  service = "sqladmin.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "servicenetworking" {
  project = var.project_id
  service = "servicenetworking.googleapis.com"
  disable_on_destroy = false
}

# Private IP address range for service networking
resource "google_compute_global_address" "private_ip_address" {
  name          = "private-ip-address"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.glen_network.id
}

# Service networking connection
resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.glen_network.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_address.name]
  depends_on             = [google_project_service.servicenetworking]
}

# Cloud SQL インスタンス
resource "google_sql_database_instance" "glen_postgres" {
  depends_on = [
    google_project_service.sqladmin,
    google_service_networking_connection.private_vpc_connection
  ]
  name             = "glen-postgres"
  database_version = "POSTGRES_15"
  region           = var.region
  
  settings {
    tier = "db-f1-micro"
    
    disk_size = 10
    disk_type = "PD_SSD"
    
    backup_configuration {
      enabled                        = true
      start_time                     = "03:00"
      point_in_time_recovery_enabled = false
      backup_retention_settings {
        retained_backups = 7
      }
    }
    
    ip_configuration {
      ipv4_enabled                                  = true
      private_network                               = google_compute_network.glen_network.id
      enable_private_path_for_google_cloud_services = true
      require_ssl                                   = false
    }
    
    database_flags {
      name  = "log_statement"
      value = "all"
    }
  }
  
  deletion_protection = false
}

resource "google_sql_database" "glen_db" {
  name     = "glen_prod"
  instance = google_sql_database_instance.glen_postgres.name
}

resource "google_sql_user" "glen_user" {
  name     = "glen_user"
  instance = google_sql_database_instance.glen_postgres.name
  password = var.db_password
}


# Cloud Memorystore (Redis)
resource "google_redis_instance" "glen_redis" {
  name           = "glen-redis"
  tier           = "BASIC"
  memory_size_gb = 1
  region         = var.region
  
  authorized_network = google_compute_network.glen_network.id
}

# GKE クラスタ
resource "google_container_cluster" "glen_cluster" {
  name     = "glen-cluster"
  location = var.zone
  
  remove_default_node_pool = true
  initial_node_count       = 1
  deletion_protection      = false
  
  network    = google_compute_network.glen_network.name
  subnetwork = google_compute_subnetwork.glen_subnet.name
  
  ip_allocation_policy {
    cluster_ipv4_cidr_block  = "10.1.0.0/16"
    services_ipv4_cidr_block = "10.2.0.0/16"
  }
  
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }
  
  # Add DNS and networking improvements
  dns_config {
    cluster_dns        = "CLOUD_DNS"
    cluster_dns_scope  = "CLUSTER_SCOPE"
    cluster_dns_domain = "cluster.local"
  }
  
  # Enable required addons
  addons_config {
    http_load_balancing {
      disabled = false
    }
    horizontal_pod_autoscaling {
      disabled = false
    }
    gce_persistent_disk_csi_driver_config {
      enabled = true
    }
  }
  
  # Release channel for stable updates
  release_channel {
    channel = "REGULAR"
  }
  
  # Network policy
  network_policy {
    enabled = false
  }
  
  # Cluster autoscaling
  cluster_autoscaling {
    enabled = false
  }
}

resource "google_container_node_pool" "glen_nodes" {
  name       = "glen-nodes"
  location   = var.zone
  cluster    = google_container_cluster.glen_cluster.name
  node_count = 1
  
  node_config {
    machine_type = "e2-small"  # 2GB RAM for stable operation
    disk_size_gb = 20
    disk_type    = "pd-standard"
    
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
    
    workload_metadata_config {
      mode = "GKE_METADATA"
    }
    
    # Security and stability improvements
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
  }
  
  management {
    auto_repair  = true
    auto_upgrade = true
  }
  
  # Prevent node pool replacement during updates
  lifecycle {
    ignore_changes = [
      node_config[0].taint,
    ]
  }
}

# Cloud Load Balancer
resource "google_compute_global_address" "glen_ip" {
  name = "glen-ip"
}

# Secret Manager
resource "google_secret_manager_secret" "jwt_secret" {
  secret_id = "jwt-secret"
  
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "jwt_secret_version" {
  secret      = google_secret_manager_secret.jwt_secret.id
  secret_data = var.jwt_secret
}

resource "google_secret_manager_secret" "db_password_secret" {
  secret_id = "db-password"
  
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "db_password_version" {
  secret      = google_secret_manager_secret.db_password_secret.id
  secret_data = var.db_password
}


# Service Account for Workload Identity
resource "google_service_account" "glen_sa" {
  account_id   = "glen-service-account"
  display_name = "Glen Service Account"
}

resource "google_project_iam_member" "glen_sa_sql" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.glen_sa.email}"
}

resource "google_project_iam_member" "glen_sa_secret" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.glen_sa.email}"
}

# Cloud Storage for static assets
resource "google_storage_bucket" "glen_assets" {
  name     = "${var.project_id}-assets"
  location = var.region
  
  uniform_bucket_level_access = true
  
  versioning {
    enabled = false
  }
  
  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age = 30
    }
  }
}

# Output values
output "cluster_name" {
  value = google_container_cluster.glen_cluster.name
}

output "cluster_zone" {
  value = google_container_cluster.glen_cluster.location
}

output "database_ip" {
  value = google_sql_database_instance.glen_postgres.ip_address.0.ip_address
}

output "redis_host" {
  value = google_redis_instance.glen_redis.host
}

output "load_balancer_ip" {
  value = google_compute_global_address.glen_ip.address
}

output "service_account_email" {
  value = google_service_account.glen_sa.email
}