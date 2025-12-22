from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_domain_encryption_enabled(Check):
    def execute(self):
        findings = []
        for domain in sagemaker_client.sagemaker_domains:
            report = Check_Report_AWS(metadata=self.metadata(), resource=domain)
            report.status = "PASS"
            report.status_extended = f"SageMaker Studio domain {domain.name} has KMS encryption enabled."
            if not domain.kms_key_id:
                report.status = "FAIL"
                report.status_extended = f"SageMaker Studio domain {domain.name} does not have KMS encryption enabled."

            findings.append(report)

        return findings
