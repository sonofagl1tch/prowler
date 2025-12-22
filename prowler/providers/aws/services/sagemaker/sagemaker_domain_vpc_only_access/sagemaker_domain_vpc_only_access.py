from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_domain_vpc_only_access(Check):
    def execute(self):
        findings = []
        for domain in sagemaker_client.sagemaker_domains:
            report = Check_Report_AWS(metadata=self.metadata(), resource=domain)
            report.status = "PASS"
            report.status_extended = f"SageMaker Studio domain {domain.name} is configured with VPC-only network access."
            if domain.app_network_access_type != "VpcOnly":
                report.status = "FAIL"
                report.status_extended = f"SageMaker Studio domain {domain.name} is not configured with VPC-only network access."

            findings.append(report)

        return findings
