# Provider permission checklist

CertHarbor is read-only against providers. The current adapters are fixture-backed contract adapters; live API clients must use the scopes below and must not request create, update, delete, certificate download, deployment, or DNS-record write permissions.

Provider permission names change over time. Verify the final policy against the linked provider reference before deploying a live adapter.

## Alibaba Cloud

Use a dedicated RAM user or role with a short-lived access mechanism where possible.

Required read actions for the planned adapter:

- `alidns:DescribeDomains`
- `alidns:DescribeDomainInfo`
- `yundun-cert:ListCert` or `yundun-cert:ListUserCertificateOrder`, depending on whether the account uses the current Certificate Management Service API or the original certificate API.

Do not grant `AddDomain`, `UpdateDomain`, `DeleteDomain`, certificate issuance, deployment, download, or revoke actions. Alibaba documents the DNS action `alidns:DescribeDomainInfo` as a read operation and the certificate list actions in its RAM authorization references:

- <https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-describedomaininfo>
- <https://www.alibabacloud.com/help/en/ssl-certificate/developer-reference/api-cas-2020-06-30-listcert>
- <https://www.alibabacloud.com/help/en/ssl-certificate/developer-reference/api-cas-2020-04-07-ram>

## Tencent Cloud / DNSPod

Use a dedicated CAM user or role with a restricted policy and a secret ID/secret key supplied only at connection creation.

Required read actions for the planned adapter:

- DNSPod: `DescribeDomainList`, `DescribeDomain`, and the read-only domain/zone detail actions used by the selected inventory path.
- SSL Certificate: `DescribeCertificates` and `DescribeCertificate` (or `DescribeCertificateDetail` where the account/API version requires it).

Do not grant DNS record mutation, domain transfer, certificate application, replacement, upload, deletion, or download actions. Tencent documents the DNSPod endpoint and request model, and the SSL certificate list/detail APIs here:

- <https://cloud.tencent.com/document/product/1427/56187>
- <https://cloud.tencent.com/document/api/1427/56173>
- <https://cloud.tencent.com/document/api/400/41671>
- <https://cloud.tencent.com/document/product/400/41674>

## AWS

Prefer an IAM role with an external ID or workload identity. If a user or access key is required, use a dedicated read-only identity and restrict the account/regions in the deployment boundary.

Minimum actions for Route 53 and ACM inventory:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "route53:ListHostedZones",
        "route53:ListHostedZonesByName",
        "route53:GetHostedZone",
        "route53:ListResourceRecordSets",
        "route53:ListTagsForResource",
        "acm:ListCertificates",
        "acm:DescribeCertificate",
        "acm:ListTagsForCertificate"
      ],
      "Resource": "*"
    }
  ]
}
```

ACM is regional, so the connection must declare the regions to scan. CertHarbor must never request `acm:GetCertificate` unless a future feature explicitly needs the public certificate body; private keys and certificate exports are out of scope. AWS maintains the action references for [ACM](https://docs.aws.amazon.com/service-authorization/latest/reference/list_acm.html) and [Route 53](https://docs.aws.amazon.com/service-authorization/latest/reference/list_route53.html).

## Cloudflare

Use an API Token, scoped to the target account and zones. Do not use a Global API Key for new deployments.

Minimum token permissions:

- `Zone Read` for zone/domain inventory.
- `DNS Read` if the adapter reads DNS records or nameserver metadata.
- `SSL and Certificates Read` for certificate-management objects.

Grant the token only the target zone resources. Do not grant `Zone Edit`, `DNS Write`, `SSL and Certificates Edit`, or unrelated account permissions. Cloudflare’s permission reference and token guidance are available at:

- <https://developers.cloudflare.com/fundamentals/api/reference/permissions/>
- <https://developers.cloudflare.com/fundamentals/api/get-started/create-token/>

## Adapter boundary

Every live adapter must return:

- provider request ID and safe error classification;
- explicit capability flags and unsupported fields;
- stable source IDs and source URLs;
- pagination progress and bounded retry behavior;
- no credential values in errors, logs, audit events, or API responses.

Fixture adapters remain available for deterministic tests and local demo mode. They are not evidence that live provider synchronization is configured.
