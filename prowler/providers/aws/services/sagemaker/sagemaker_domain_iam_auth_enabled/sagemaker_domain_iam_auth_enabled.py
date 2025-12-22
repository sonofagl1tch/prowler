from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_domain_iam_auth_enabled(Check):
    def execute(self):
        findings = []
        for domain in sagemaker_client.sagemaker_domains:
            report = Check_Report_AWS(metadata=self.metadata(), resource=domain)
            report.status = "PASS"
            report.status_extended = f"SageMaker Studio domain {domain.name} uses IAM authentication."
            if domain.auth_mode != "IAM":
                report.status = "FAIL"
                report.status_extended = f"SageMaker Studio domain {domain.name} does not use IAM authentication, uses {domain.auth_mode} instead."

            findings.append(report)

        return findings
