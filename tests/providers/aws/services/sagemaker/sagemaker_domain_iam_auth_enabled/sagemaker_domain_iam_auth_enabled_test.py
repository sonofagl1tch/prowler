from unittest import mock

from prowler.providers.aws.services.sagemaker.sagemaker_service import Domain
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

test_domain_id = "d-test123"
test_domain_name = "test-domain"
domain_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:domain/{test_domain_id}"


class Test_sagemaker_domain_iam_auth_enabled:
    def test_no_domains(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_domains = []

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_domain_iam_auth_enabled.sagemaker_domain_iam_auth_enabled.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_domain_iam_auth_enabled.sagemaker_domain_iam_auth_enabled import (
                sagemaker_domain_iam_auth_enabled,
            )

            check = sagemaker_domain_iam_auth_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_domain_iam_auth(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_domains = [
            Domain(
                arn=domain_arn,
                id=test_domain_id,
                name=test_domain_name,
                status="InService",
                region=AWS_REGION_EU_WEST_1,
                auth_mode="IAM",
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_domain_iam_auth_enabled.sagemaker_domain_iam_auth_enabled.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_domain_iam_auth_enabled.sagemaker_domain_iam_auth_enabled import (
                sagemaker_domain_iam_auth_enabled,
            )

            check = sagemaker_domain_iam_auth_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SageMaker Studio domain {test_domain_name} uses IAM authentication."
            )
            assert result[0].resource_id == test_domain_id
            assert result[0].resource_arn == domain_arn

    def test_domain_sso_auth(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_domains = [
            Domain(
                arn=domain_arn,
                id=test_domain_id,
                name=test_domain_name,
                status="InService",
                region=AWS_REGION_EU_WEST_1,
                auth_mode="SSO",
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_domain_iam_auth_enabled.sagemaker_domain_iam_auth_enabled.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_domain_iam_auth_enabled.sagemaker_domain_iam_auth_enabled import (
                sagemaker_domain_iam_auth_enabled,
            )

            check = sagemaker_domain_iam_auth_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SageMaker Studio domain {test_domain_name} does not use IAM authentication, uses SSO instead."
            )
            assert result[0].resource_id == test_domain_id
            assert result[0].resource_arn == domain_arn
