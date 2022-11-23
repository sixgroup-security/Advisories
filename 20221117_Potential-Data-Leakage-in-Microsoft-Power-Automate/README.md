# Potential Data Leakage in Microsoft Power Automate

## Executive Summary

Microsoft Power Automate allows users to automate tasks via cloud flows. Any information that is processed by such flows (e.g., confidential emails and attachments) are subject to become potentially accessible by anyone on the internet without any further checks.

As URLs are regularly stored by web proxies, web application firewalls (WAF) or search engines such as Google/Bing, it increases the likelihood that information are disclosed to third-parties and therefore represents a violation of security best practices.

---

**Table of Contents**

- [Potential Data Leakage in Microsoft Power Automate](#potential-data-leakage-in-microsoft-power-automate)
  * [Executive Summary](#executive-summary)
  * [Affected Component](#affected-component)
  * [Introduction](#introduction)
  * [Proof of Concept](#proof-of-concept)
    + [Getting access to Power App descriptors through package export](#getting-access-to-power-app-descriptors-through-package-export)
    + [Getting access to Power App descriptors through PowerShell](#getting-access-to-power-app-descriptors-through-powershell)
    + [Getting access to the payload of a certain flow action such as email exfiltration](#getting-access-to-the-payload-of-a-certain-flow-action-such-as-email-exfiltration)
    + [Getting access to a list of all action payloads at once for a certain cloud flow run](#getting-access-to-a-list-of-all-action-payloads-at-once-for-a-certain-cloud-flow-run)
    + [Entity export from Power Apps Dataverse](#entity-export-from-power-apps-dataverse)
    + [Getting access to Power Apps descriptors through Power Automate](#getting-access-to-power-apps-descriptors-through-power-automate)
    + [Download a PBIX version of a report in the Power BI service](#download-a-pbix-version-of-a-report-in-the-power-bi-service)
    + [SAS URIs to access the Azure Storage under the Dataverse](#sas-uris-to-access-the-azure-storage-under-the-dataverse)
  * [Expected Results](#expected-results)
  * [Timeline](#timeline)

---

## Affected Component

At least Microsoft Power Apps, Power BI and Power Automate but additional Microsoft cloud applications might also be affected.

## Introduction

Shared access signatures (SAS) are web addresses (URI) that are temporarily valid (e.g., for 2 days) and grant any user, who is in possession of the URI, access to the respective cloud storage resource (e.g., a specific file with classified data).

Our tests on Microsoft Power Apps, Power BI and Power Automate showed that SAS URIs are not only manually created by users but are also automatically created by the cloud applications in the background. This potentially leads to a high number of temporarily valid SAS URIs. Furthermore, the creation of SAS URIs is not logged/audited (see separate vulnerability report) and as a result, there is zero visibility.

*	on how many valid SAS URIs exist/existed,
*	on who uses/used the SAS URIs from where and
*	to which data SAS URIs grant/granted access to.

Finally, Conditional Access policies are not enforced on SAS URIs (covered by this report). This zero transparency combined with unrestricted access makes SAS URIs an ideal means for [data exfiltration](https://attack.mitre.org/tactics/TA0010/).

As a result, it was decided to deactivate Microsoft Power Platform for all users and to assess the need and conditions for continuing the existing implementations. Due to the missing logging and automatic generation, it cannot be ruled out that SAS URIs are not used in other Microsoft cloud applications as well, which represents a security risk of unknown extend.

## Proof of Concept

This section provides some examples where SAS URIs are created in Power Apps, Power BI and Power Automate and how they could be misused for data exfiltration. The objective is to demonstrate that SAS URIs are extensively used by Microsoft and that no Conditional Access Policies are enforced on them.

### Getting access to Power App descriptors through package export 

Power Apps allows the creation of applications. A malicious internal actor could save sensitive information directly into the descriptor (blueprint) of a Power Apps application and exfiltrate it via the package export.

In order to execute this type of exfiltration, a Canvas app must exist in Power Apps’ make portal and we have to execute the following steps:

1. Open the [Power Apps](https://make.powerapps.com) make portal by opening the following link and then click on menu item *Apps*.

2. In the *Apps* menu, select an app of type *Canvas* and click button *Export package* (see figure below).

![Figure 1](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig1.png)

3. On the *Export package* page, enter arbitrary information into the Description field (limited to 1024 characters). For example, the next images documents how the first bytes of the binary file ```C:\windows\system32\calc.exe``` could be exfiltrated via the package’s description field.

![Figure 2](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig2.png)

4. After clicking *Export*, the package is downloaded. In addition, a SAS URI is created

![Figure 3](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig3.png)

As of September 19, 2022, the resulting SAS URI (see below) is valid for 1 hour but can be downloaded from any IT system and source IP address as documented below. This confirms that **no** Conditional Access Policies are enforced on SAS URIs.

```https://bapfeblobprodam.blob.core.windows.net/20220919t000000z0596bdff626640d88de0c3a2e0781a58/Exportdata_20220919095735.zip?sv=2018-03-28&sr=c&sig=9niVFtnWi8wF3nMgLQ8iom0dB6bXoBiunRrkiiKGdzs%3D&se=2022-09-19T10%3A57%3A36Z&sp=rl```

![Figure 4](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig4.png)

Note that the download file is ZIP compressed, which among other things contains the description field.

### Getting access to Power App descriptors through PowerShell

App information can also be accessed via the PowerShell module ```Microsoft.PowerApps.Administration.PowerShell``` by executing the following PowerShell commands:

```
PS C:\> powershell -exec bypass
[…]
PS C:\> Add-Power AppsAccount
[…]
PS C:\> $app = (Get-PowerApp)[0]
PS C:\> $app.Internal.properties.appUris.documentUri.readonlyValue
https://pafeblobprodam-secondary.blob.core.windows.net/20220908t000000z5c6a60c9e0e9489293e97f2d90c47ca8/document.msapp?sv=2018-03-28&sr=c&sig=oOFq4%2FOkRQ5exeW03OpCJ55eC88RSJeEWGN4vyA2j34%3D&se=2022-09-23T20%3A00%3A00Z&sp=rl
PS C:\> get-date
Montag, 19. September 2022 13:20:43
```

![Figure 5](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig5.png)

As highlighted in above, the SAS URI was requested on September 19, 2022 and the SAS URI expiration date (see GET parameter ```se```) is on September 23, 2022. Consequently, the SAS URI is valid for several days.

As documented in below, Conditional Access Policies are not enforced on the previously created SAS URI allowing the download from any IT system and public source IP address.

![Figure 6](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig6.png)

### Getting access to the payload of a certain flow action such as email exfiltration

Power Automate allows the creation of so-called flows. Flows are automatically executed as soon as a certain event occurs (e.g., email is received). Flows create SAS URIs for all trigger inputs and outputs, which can then be used by a malicious internal actors to exfiltrate the corresponding data.

First, we need to create a basic automated cloud flow. This flow is triggered when an email arrives in Outlook 365.

![Figure 7](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig7.png)

As soon as an email is received and processed by the cloud flow, we can download the email’s content via the cloud flow’s history.

![Figure 8](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig8.png)

As of September 19, 2022, the resulting SAS URI (see below) is valid for 1 hour but can be downloaded from any IT system and source IP address.

```
https://prod-71.westeurope.logic.azure.com/workflows/b92c36c2b0e548ea804e92b614e7a4e8/runs/08585389039233391139652680427CU91/contents/TriggerOutputs?api-version=2017-07-01&se=2022-09-19T15%3A00%3A00.0000000Z&sp=%2Fruns%2F08585389039233391139652680427CU91%2Fcontents%2FTriggerOutputs%2Fread&sv=1.0&sig=uIuzo5ZdkV_kTwI3XOUJwbFCvL-XSsJjjQykqN1fU4Y
```

![Figure 9](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig9.png)

The SAS URI allows accessing the content of the email that was processed by the cloud flow trigger from any source IP address. Consequently, no Conditional Access Policies are enforced on SAS URIs.

### Getting access to a list of all action payloads at once for a certain cloud flow run

This case is similar to the one described above. In this case, however, we can download all emails that have been processed by the cloud flow in the past 28 days. We can perform the download by executing the following steps:

1. We open a flow, which has at least one run, by clicking on the flow’s name

![Figure 10](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig10.png)

2. In the flow’s details, in the *28-day run history* section, we click on *All runs*.

![Figure 11](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig11.png)

3. Next, in the run history, we click on button *Get .csv* file.

4. After clicking the button, the download file is created, which is then accessible via the link *Download file*.

![Figure 12](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig12.png)

The download link represents a SAS URI, which is documented below. Note that this SAS URI does not contain an explicit expiration data in the URI (GET parameter ```se```). Therefore, the exact expiration time is unknown.

```https://datastoragetip0psrpfeweu.blob.core.windows.net/4600bdb7fdd72516/flow-dfbd031d-20db-4b9d-90fd-7e223d28282b-20220919t121652z.csv?sv=2018-03-28&sr=b&si=SASpolicy&sig=ZBrb%2FYJYo%2F%2BegVTCJ4hRqg7zSypTAWMJzLG0Gx7djQg%3D&spr=https&rsct=application%2Foctet-stream&rscd=attachment%3B%20filename%3D%22flow-dfbd031d-20db-4b9d-90fd-7e223d28282b-20220919t121652z.csv%22```

Conditional Access Policies are not enforced on the previously created SAS URI allowing the download from any IT system and public source IP address.

![Figure 13](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig13.png)

### Entity export from Power Apps Dataverse

Dataverse contains portions of the information stored in it in the form of entities (tables) and records (rows). The information in the Dataverse can be accessed via Power Automate flows, Power Apps canvas and model-driven apps, via REST API calls and through the Power Apps make portal.

In the Power Apps make portal on the user interface, the data of an Entity can be exported by a user. Thereby, the exported file is made available by the system through a SAS URI.

In order to exfiltrate entity data, we have to execute the following steps:

1. We open the [Power Apps](https://make.powerapps.com) make portal

2. In the menu Dataverse and submenu Tables, click on a table (e.g., Account).

![Figure 14](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig14.png)

3. On the table’s page, click button *Export > Export data*.

![Figure 15](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig15.png)

4. After clicking the button *Export data*, a download link in form of a SAS URI is automatically created 

![Figure 16](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig16.png)

The full SAS URI is documented below and is valid for approximately one day.

```https://d365integstorageprodwe.blob.core.windows.net/integratorapp-filestorage/ExportedFiles_ab4955ef-440b-475e-981f-ad56ae69f0e3.zip?sv=2018-03-28&sr=b&sig=O6OpjMJnww5iyk7n%2FEWPL401ys%2Flr8m4OBIf6zmlzC0%3D&st=2022-09-18T12%3A58%3A17Z&se=2022-09-20T12%3A58%3A17Z&sp=rwd```

Conditional Access Policies are not enforced on the previously created SAS URI allowing the download from any IT system and public source IP address.

![Figure 17](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig17.png)

The download contains a ZIP-compressed CSV file ```accounts.csv```.

### Getting access to Power Apps descriptors through Power Automate

Malicious internal actors could save sensitive information directly into the descriptor (blueprint) of a Power Apps application and exfiltrate this data via a SAS URI created by Power Automate.

For the successful execution of this use case, we have to execute the following steps:

1. In the Power Apps make portal, create a flow that gets all Power Apps applications to which access is given.

![Figure 18](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig18.png)

2. Next, run the newly created flow

![Figure 19](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig19.png)

3. If the *Secure Input* and/or *Secure Output* options are not set for an action, click on the Show raw outputs link:

![Figure 20](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig20.png)

4. In the opening right-pane, search for the ```readonlyvalue``` attribute, which contains the SAS URI.

![Figure 21](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig21.png)

5. Afterwards, open this URI from any machine. The package is downloaded and any information that is saved directly into the blueprint of an application will appear in there.

### Download a PBIX version of a report in the Power BI service

When creating a dashboard in Power BI Desktop, the system saves the data model into a PBIX file. 

![Figure 22](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig22.png)

The ```DataModel``` file within the PBIX file (see screenshot above) is saved in XPress9 Compression format and contains all the data that was imported at the time of the generation of the file. When publishing the PBIX file to the Power BI online service, the complete file is uploaded and is used to generate the reports in the cloud.

When downloading the file from the Power BI service, the published version of the file will be downloaded containing all data. The up-to-dateness of the data depends on the query type:

- **direct query**: then the data is the one that was saved into it at the time of publishing.
- **import query**: the data of the last refresh.

The lifetime of these SAS URIs is up to 1 hour.

In order to exfiltrate data via this possibility, execute the following steps:

1. Create a Power BI report in Power BI Desktop. Note that the file size of the report must be bigger than 50 MB. 
2. Publish the report to a Power BI Workspace.
3. Open the report in [Power BI Online](https://app.powerbi.com/).
4. Press keyboard key F12 in the web browser to start the web browser’s developer mode. There, start recording the network traffic.
5. Click on the ellipsis next to the report or the connected dataset and click menu item *Download this file*.

![Figure 23](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig23.png)

![Figure 24](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig24.png)

6. Afterwards, stop the network capturing and look for the links which end with ```.pbix```.

![Figure 25](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig25.png)

7. Finally, copy that link and test it from anywhere. This will give the possibilities to download the report in the PBIX format. 

### SAS URIs to access the Azure Storage under the Dataverse

A system administrator of a Dataverse enhanced environment can create a SAS URI that can be used to access the Azure file storage under the Dataverse. The action plan on how to access this storage is documented in the [Access your storage](https://learn.microsoft.com/en-us/power-platform/admin/storage-sas-token) with a SAS token article, although the permission set needs to be adjusted a bit. Once having read/write access to the storage, it can be accessed via any means that can handle the SAS URIs for the storage device, for example the [Microsoft Azure Storage Explorer](https://azure.microsoft.com/en-us/features/storage-explorer/) application.  Files stored in the Azure Storage are not subject to any SIX controls or scanning. Depending on the Power Platform solution using the Dataverse for file storage, the files used in the solution can be exposed this way. The SAS URI generated for the Azure Storage is valid for 1 hour.

The steps necessary to perform this type of attack are the following:

1. As a system administrator of an environment that has a Dataverse, we go to the [Power Apps make portal](https://make.powerapps.com/)

2. In the top-right corner of the window, click on the gear icon and choose *Session Details*.

![Figure 26](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig26.png)

3. In the session details dialog, copy the *Instance url* value.

![Figure 27](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig27.png)

4. Open the below URL in a new browser tab and copy the value of the ```containerendpoint``` attribute: 

```https://<InstanceURL>/api/data/v9.1/datalakefolders```

![Figure 28](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig28.png)

5. Open the below URL in a new browser tab and copy the value of the SASToken:

```https://<InstanceURL>/api/data/v9.1/RetrieveAnalyticsStoreAccess(Url=@a,ResourceType='Folder',Permissions='Read,Add,Create,Write,Delete,List')?@a='<containerurl>/CDS'```

![Figure 29](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig29.png)

6. Install and launch the [Microsoft Azure Storage Explorer](https://azure.microsoft.com/en-us/features/storage-explorer/).

7. When the dialog appears, choose the *ADLS Gen2 container or directory* option.

![Figure 30](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig30.png)

8. In the *Select Connection Method* step, select *Shared access signature URL (SAS)*.

![Figure 31](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig31.png)

9. In the *Enter Connection Info* step, specify a name for our connection and paste the below URL into the *Blob container or directory SAS URL* field:

```https://<containerurl>/CDS?<SASToken>```

![Figure 32](https://github.com/sixgroup-security/Advisories/blob/main/20221117_Potential-Data-Leakage-in-Microsoft-Power-Automate/img/fig32.png)

10. Finally, click *Next and Connect*.

At this point, it is possible to up- and download files through the Microsoft Azure Storage Explorer for 1 hour until a new SAS URI needs to be generated.

## Expected Results

Microsoft customers should have the possibility to effectively and globally deactivate the usage of SAS URIs. If this is not possible, then the following preventive and detective measures should at least be implemented:

1. The creation and usage of SAS URIs should be logged so that Microsoft cloud customers can detect and respond to potential data leakages. In addition, customers can make an assessment how heavily certain Microsoft cloud applications rely on SAS URIs and whether this is within their risk appetite.

2. Microsoft cloud customers should be able to enforce their Conditional Access Policies also on SAS URIs.

## Timeline

| Date       | Description                                                                                                                        |
|------------|------------------------------------------------------------------------------------------------------------------------------------|
| 26.09.2022 | SIX reported issue. |
| 21.10.2022 | Microsoft changed issue status from *New* to *Review / Repro*. |
| 08.11.2022 | Microsoft changed issue status from *Review / Repro* to *Develop*. |
| 08.11.2022 | Microsoft closed case. *"MSRC has investigated this issue and concluded that this does not pose an immediate threat that requires urgent attention due to low impact."* |
| 17.11.2022 | Public disclosure of vulnerability. |

