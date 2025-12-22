"""
Tests for SageMaker Studio Domain logic.
"""

from unittest.mock import MagicMock, patch
from prowler.providers.aws.services.sagemaker.sagemaker_service import (
    SageMaker,
    Domain,
)


class TestSageMakerDomains:
    """Test suite for SageMaker Domains."""

    def test_list_domains(self):
        """Test that _list_domains correctly parses domain information and handles pagination."""
        audit_info = MagicMock()
        audit_info.audited_partition = "aws"
        audit_info.audited_account = "123456789012"
        audit_info.audit_resources = None

        regional_client = MagicMock()
        regional_client.region = "us-east-1"

        # Mock pagination
        paginator = MagicMock()
        regional_client.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {
                "Domains": [
                    {
                        "DomainArn": "arn:aws:sagemaker:us-east-1:123456789012:domain/d-123",
                        "DomainId": "d-123",
                        "DomainName": "test-domain",
                        "Status": "InService",
                    }
                ]
            }
        ]

        # Use patch to mock init calls
        with patch.object(SageMaker, "__init__", return_value=None):
            sagemaker_service = SageMaker(audit_info)
            sagemaker_service.regional_clients = {"us-east-1": regional_client}
            sagemaker_service.sagemaker_domains = []
            sagemaker_service.audit_info = audit_info
            sagemaker_service.audit_resources = audit_info.audit_resources

            # Execute
            sagemaker_service._list_domains(regional_client)

            # verify
            assert len(sagemaker_service.sagemaker_domains) == 1
            domain = sagemaker_service.sagemaker_domains[0]
            assert domain.arn == "arn:aws:sagemaker:us-east-1:123456789012:domain/d-123"
            assert domain.id == "d-123"
            assert domain.name == "test-domain"
            assert domain.status == "InService"
            assert domain.region == "us-east-1"

    def test_describe_domain(self):
        """Test that _describe_domain correctly populates detailed configuration."""
        audit_info = MagicMock()

        regional_client = MagicMock()
        regional_client.region = "us-east-1"
        regional_client.describe_domain.return_value = {
            "AuthMode": "SSO",
            "AppNetworkAccessType": "VpcOnly",
            "VpcId": "vpc-123",
            "SubnetIds": ["subnet-1"],
            "KmsKeyId": "kms-key-1",
        }

        domain = Domain(
            arn="arn:aws:sagemaker:us-east-1:123456789012:domain/d-123",
            id="d-123",
            name="test-domain",
            status="InService",
            region="us-east-1",
        )

        with patch.object(SageMaker, "__init__", return_value=None):
            sagemaker_service = SageMaker(audit_info)
            sagemaker_service.regional_clients = {"us-east-1": regional_client}

            sagemaker_service._describe_domain(domain)

            assert domain.auth_mode == "SSO"
            assert domain.app_network_access_type == "VpcOnly"
            assert domain.vpc_id == "vpc-123"
            assert domain.kms_key_id == "kms-key-1"
