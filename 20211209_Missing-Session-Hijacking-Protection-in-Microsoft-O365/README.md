# Missing Session Hijacking Protection in Microsoft O365

## Affected Component

All tests were performed on Outlook 365 but additional O365 services like SharePoint might also be affected.

## Summary

As documented in this [article](https://blog.google/threat-analysis-group/phishing-campaign-targets-youtube-creators-cookie-theft-malware/) by Google, cookie theft gains popularity among adversaries.

Testing such cookie theft scenario on Outlook 365 showed that Outlook 365 allows the successful simultaneous usage of the same authorized session cookies from different web browsers (different user agent strings) and/or public IP addresses. Such simultaneous usage, however, is a strong indicator that session cookies were stolen and are re-used by another entity. Therefore, web applications with high security requirements (e.g., e-banking web applications) usually invalidate such compromised session information as soon as such indicators arise. This is not the case for Outlook 365 and therefore, is reported in this vulnerability report.

## Proof of Concept

SIX simulated a session hijacking attack on Outlook 365 to test O365’s resilience against cookie theft attacks by executing the following steps.

First, SIX successfully logged into the Outlook 365 web application via an Intune-managed device. The successful login is documented in Figure 1.

![Figure 1 : Successful login to outlook.office.com.](/assets/images/figure_1.png)

Afterwards, the session cookies listed in Figure 1 were transferred to a second third-party non-Intune managed device. The import process on this second device is documented in Figure 2.

![Figure 2 : SIX imported the cookies of Figure 1 into a web browser on another non-Intune-managed device.](/assets/images/figure_2.png)

After the import, the web application was refreshed and as depicted in Figure 3, access to the user’s Outlook 365 account was possible from this second device. Thereby, SIX could read as well as send emails. Note that the user agent strings as well as the public IP addresses differ between the original Intune-managed (see Figure 1) and the third party non-Intune-managed (see Figure 3) device.

![Figure 3: Solen session information can be re-used on third-party devices.](/assets/images/figure_3.png)

Finally, SIX refreshed the Outlook 365 page on the Intune-managed device and afterwards on the non-Intune-managed device to determine if the simultaneous usage triggers a session invalidation. Thereby, the session on the non-Intune-managed device remained valid.

The made observations indicate that Outlook 365 does implement basic session hijacking protection mechanisms.

## Expected Result

Session cookies should be invalidated by O365 services as soon as one of the following conditions are met:

- The user agent string repeatedly (e.g., at least three times) changes for the same session.
- The public IP address repeatedly (e.g., at least three times) changes for the same session.

A session invalidation due to the above conditions should also trigger an alert in Microsoft Sentinel.

## Timeline

| Date       | Description                                                                                                                        |
|------------|------------------------------------------------------------------------------------------------------------------------------------|
| 21.10.2021 | SIX received a threat intelligence notification about attacks where 2FA is defeated via pass-the-cookie/session hijacking attacks. |
| 21.10.2021 | SIX tested the session hijacking attack on Outlook 365  and confirmed that such an attack is possible. |
| 22.10.2021 | SIX repeated the session hijacking attack on Outlook 365 and tried to develop detection capabilities. The tests have shown that: <ul><li>It is possible to leverage this attack for O365.</li><li>It is not possible to detect the attack.</li><li>It is not possible to prevent the attack.</li></ul> |
| 26.10.2021 | SIX reported one of the identified vulnerabilities to Microsoft. |
| 27.10.2021 | SIX received acknowledgement from Microsoft. |
| 28.10.2021 | Microsoft created the vulnerability report (submission number VULN-056667). |
| 05.12.2021 | SIX performed additional tests to assess the vulnerabilities and created this report. |
| 06.12.2021 | Mandiant published the article “[Suspected Russian Activity Targeting Government and Business Entities Around the Globe](https://www.mandiant.com/resources/russian-targeting-gov-business)” , which confirms that cookie theft attacks are already actively executed on Microsoft 365 environment. |
| 06.12.2021 | SIX resubmitted this vulnerability to Microsoft. |
| 07.12.2021 | Microsoft responded and did not recognize the vulnerability stating “*this appears to be working as expected for this functionality and this case would be closed out for security tracking*”. |
| 07.12.2021 | SIX decides to publish the vulnerability report as Microsoft has no intention to work on this. |
