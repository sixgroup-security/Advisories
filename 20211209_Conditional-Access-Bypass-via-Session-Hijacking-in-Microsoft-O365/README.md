# Conditional Access Policy Bypass via Session Hijacking in Microsoft O365

## Affected Component

All tests were performed on Outlook 365 but additional O365 services like SharePoint might also be affected.

## Summary

As documented in this [article](https://blog.google/threat-analysis-group/phishing-campaign-targets-youtube-creators-cookie-theft-malware/) by Google, cookie theft gains popularity among adversaries.

Testing such cookie theft scenario on Outlook 365 showed that Outlook 365 allows the successful simultaneous usage of the same authorized session cookies from different web browsers (different user agent strings) and/or public IP addresses. Such simultaneous usage, however, is a strong indicator that session cookies were stolen and are re-used by another entity. Therefore, web applications with high security requirements (e.g., e-banking web applications) usually invalidate such compromised session information as soon as such indicators arise. This is not the case for Outlook 365 and therefore, is already reported in a dedicated vulnerability report (see VULN-058209).

In addition, the tests showed that stealing session cookies from an authorized Outlook 365 session also allows bypassing existing conditional access policies. The issue of such a conditional access policy bypass is addressed in this vulnerability report.

## Background Information

As [documented](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols), the server login.microsoftonline.com is the Microsoft identity platform endpoint, which performs authentication and authorization for all registered applications like Outlook 365.

Tests showed that this endpoint also enforces the conditional access policies. The request table in Figure 1 documents the HTTP requests that are sent from the web browser to the Outlook 365 application, when Outlook 365 is accessed for the first time.

![Figure 1 : HTTP communication between web browser and Outlook 365 during first login from a Russian IP address. ](https://github.com/sixgroup-security/Advisories/blob/main/20211209_Conditional-Access-Bypass-via-Session-Hijacking-in-Microsoft-O365/figure_1.png)

As highlighted above, the first request (ID 10797) performs a redirect to the Microsoft identity platform endpoint. In HTTP request 10820, SIX entered the test user’s email address, which leads to a redirect to SIX’s ADFS. In request 10826, SIX entered the user’s password. The successful authentication to the ADFS leads to a redirect back to the Microsoft identity platform endpoint. Finally, the Microsoft identity platform endpoint determines that the user accesses Outlook 365 from an Russian IP address, which violates an existing conditional access policy and therefore prohibits access to Outlook 365.

## Proof of Concept

SIX simulated the following session hijacking attack on Outlook 365 to test O365’s resilience against cookie theft attacks by executing the following steps.

First, SIX successfully logged into the Outlook 365 web application via an Intune-managed device. The successful login is documented in Figure 2.

![Figure 2 : Successful login to outlook.office.com.](https://github.com/sixgroup-security/Advisories/blob/main/20211209_Conditional-Access-Bypass-via-Session-Hijacking-in-Microsoft-O365/figure_2.png)

Afterwards, the session cookies listed in Figure 2 were transferred to a second third-party non-Intune managed device. The import process on this second device is documented in Figure 3.

![Figure 3 : SIX imported the cookies of Figure 2 into a web browser on another non-Intune-managed device.](https://github.com/sixgroup-security/Advisories/blob/main/20211209_Conditional-Access-Bypass-via-Session-Hijacking-in-Microsoft-O365/figure_3.png)

After the import, the web application was refreshed and as depicted in Figure 4, access to the user’s Outlook 365 account was possible from the same Russian IP address as depicted in Figure 1. This confirms that conditional access policies can be bypassed by stealing session cookies.

![Figure 4: Stolen session information can be re-used on third-party devices.](https://github.com/sixgroup-security/Advisories/blob/main/20211209_Conditional-Access-Bypass-via-Session-Hijacking-in-Microsoft-O365/figure_4.png)

Figure 5 documents the HTTP requests that were exchanged between the web browser and Outlook 365 during the above mentioned cookie theft attack.

![Figure 5: HTTP communication between web browser and Outlook 365 while using stolen session cookies.](https://github.com/sixgroup-security/Advisories/blob/main/20211209_Conditional-Access-Bypass-via-Session-Hijacking-in-Microsoft-O365/figure_5.png)

By comparing the request sequences of Figure 1 and Figure 5, it becomes apparent that due to the valid stolen session cookies, the user is already authenticated to Outlook 365 and therefore, no redirect to the Microsoft identity platform endpoint is necessary. As the conditional access policies are exclusively checked by the Microsoft identity platform, this leads to the bypass of defined conditional access policies.

## Expected Results

For each HTTP request, O365 should only successfully process HTTP requests that originate from IP addresses that comply with existing conditional access policies. If there is a violation, then the current session should be invalidated on the server side to increase O365’s resilience against successful cookie theft attacks.

A session invalidation due to the above event should also trigger an alert in Microsoft Sentinel.

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
| 16.12.2021 | SIX decides to publish the vulnerability report as Microsoft has no intention to work on this. |
