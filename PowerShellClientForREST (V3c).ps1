# ***************************************************************************
# 
# File: PowerShellClientForREST (V3c).ps1
#
# Version: 3.0
# 
# Author: Igor Pagliai (MSFT)
# 
# Purpose: Show how to work directly with Azure ARM REST API using PowerShell
# 
# ---------------------------- DISCLAIMER ------------------------------------
# This script code is provided only as an example, code is "as is with no
# guarantee or waranty concerning the usability or impact on systems and 
# may be used, distributed, and modified in any way provided the parties 
# agree and acknowledge the Microsoft or Microsoft Partners have neither
# accountabilty or responsibility for results produced by use of this script.
## Microsoft will not provide any support through any means.
# ---------------------------- DISCLAIMER ------------------------------------
#
# ***************************************************************************

#region Initialization and general Variables setting #
# 
# Change Prompt to date/time:    https://technet.microsoft.com/en-us/library/hh847739.aspx
function prompt {"$(get-date)> "} 

# Check PowerShell module versions: #
$module_names='AzureRM*' 
if(Get-Module -ListAvailable |  
    Where-Object { $_.name -clike $module_names })  
{  
    (Get-Module -ListAvailable | Where-Object{ $_.Name -clike $module_names }) |  
    Select Version, Name, Author, PowerShellVersion  | Format-Table 
}  
else  
{  
    “The Azure PowerShell module is not installed.” 
}

# INIT #
$mySubID = 'Your Subsription ID'
$mySubName = 'Your Subscription Name'
$rgname = 'Your Resource Group name' 
$location = 'Your Azure Region'
$storageacccountname = 'Your default storage account name'
$storagetype = 'Standard_LRS' # Possible Values = "Standard_LRS,Standard_ZRS,Standard_GRS,Standard_RAGRS,Premium_LRS"
$myappname = 'Your App Name in Azure AD'
$myappPassword = 'Your App Password' 
$roletype = 'Owner' # Possible Built-in roles: (Owner, Reader, Contributor) 
$ADdomainName = 'Your Azure Active Directory domain name' 
#endregion
#region Intial logon to Azure AD and Global objects creation #
Login-AzureRmAccount
$subscription = Get-AzureRmSubscription –SubscriptionName $mySubName | Set-AzureRmContext
Write-Host ("Azure  TenantID [ " + $subscription.Tenant.TenantId + " ]") -ForegroundColor Yellow 
Write-Host ("Azure AccountID [ " + $subscription.Account.Id + " ]") -ForegroundColor Yellow 

# check the existance of the resource group and create one if it does not exist
if (!(Get-AzureRmResourceGroup -Name $rgname -ErrorAction SilentlyContinue)) {
    New-AzureRmResourceGroup -Name $rgname -Location $location
}

# check the existance of the ARM storage account and create one if it does not exist
if (!(Get-AzureRmStorageAccount -Name $storageacccountname -ResourceGroupName $rgname -ErrorAction SilentlyContinue)){
    New-AzureRmStorageAccount -Name $storageacccountname -ResourceGroupName $rgname  -Type $storageType -Location $location
}

# Set storage account and set as default: #
Set-AzureRmCurrentStorageAccount –ResourceGroupName $rgname –StorageAccountName $storageacccountname 
$subscription

# Check Azure quota: #
Get-AzureRmVMUsage $location

# New Azure AD application object, it will provide identity to access Azure Active Directory: #
$myapp1HomePage = 'http://' + $myappname
$myapp1URI = $myapp1HomePage

# check the existance of the resource group and create one if it does not exist
if (!($myapp1 = Get-AzureRmADApplication -IdentifierUri $myapp1URI -ErrorAction SilentlyContinue)) {
   $myapp1 = New-AzureRmADApplication –DisplayName $myappname –HomePage $myapp1HomePage –IdentifierUris $myapp1URI –Password $myappPassword 
} 

# Retrieve the ApplicationID information #
$myapp1ID = $myapp1.ApplicationId

# Now create a Service Principal for "App1": #
if (!($myapp1SP = Get-AzureRmADServicePrincipal -SearchString $myapp1.DisplayName -ErrorAction SilentlyContinue)) {
   $myapp1SP = New-AzureRmADServicePrincipal –ApplicationId $myapp1.ApplicationId  
    Write-Host ("Service Principal [ " + $myapp1SP.DisplayName + "] created with GUID [ " + $myapp1SP.Id + " ] created....") -ForegroundColor Yellow
} 

# Assign that Service Principal a role in the AAD tenant, can be scoped to single Resource Group or entire Subscription: #
try{
    # Assign to the specific Resource Group level #
    $roleassignment = New-AzureRmRoleAssignment –RoleDefinitionName $roletype –ServicePrincipalName $myapp1.ApplicationId -ResourceGroupName $rgname -ErrorAction SilentlyContinue
    Write-Host ("Assigned [ $roletype ] role at Service Principal [ " + $myapp1SP.DisplayName +" ] on Resource Group [$rgname]....") -ForegroundColor Yellow 
    # Assign to the entire subscription level #
    $roleassignment2 = New-AzureRmRoleAssignment –RoleDefinitionName $roletype –ServicePrincipalName $myapp1.ApplicationId -ErrorAction SilentlyContinue
    Write-Host ("Assigned [ $roletype ] role at Service Principal [ " + $myapp1SP.DisplayName +" ] on Subscription [ $mySubName ]....") -ForegroundColor Yellow 
}
catch{
    echo 'Error creating Role Assignment!'
}

# Helper functions #

# Find service principal by SPN  --------------------------
Get-AzureRmADServicePrincipal -SPN $myapp1SP.ServicePrincipalNames[0]

# Find service principals using Search String: #
Get-AzureRmADServicePrincipal -SearchString $myapp1SP.DisplayName

# Retrieve a list of credentials associated with an application #
# This command will retrieve all of the credential properties (but not the credential value) associated with the application: #
Get-AzureRmADAppCredential -ApplicationId $myapp1.ApplicationId

################################# Execute the steps in AAD portal as mentioned in the link below to create a new key ##########################################
#
#     Use portal to create an Azure Active Directory application and service principal that can access resources 
#     https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-create-service-principal-portal
#
#     NOTE: The username for your service principal is the APPLICATION ID (not the SPN ID), which is a GUID. 
#     When used for logging in the username needs to be given in the form “username@domain-name, the domain-name looks like <something>.onmicrosoft.com. 
#

$mysecurepassword = ConvertTo-SecureString $myappPassword -AsPlainText –Force
$myusername = "" + $myapp1.ApplicationId + "@" + $ADdomainName + ""
try{
 $mycredential = New-Object -TypeName pscredential –ArgumentList $myusername, $mysecurepassword
Write-Host ("AAD Credendial created....") -ForegroundColor Yellow 
}
catch{
    echo 'Error creating AAD Credential!'
}
# Retrieve AAD tenant name for your subscription: #
$tenant = (Get-AzureRmSubscription -SubscriptionName $mySubName).TenantId

############################## Now you have everything ready to authenticate using a service principal in AAD: ###############################

# You can add this SPN based credentials to your Azure PS profile with Add-AzureRmAccount or logon interactively using Login-AzureRmAccount and enter credentials:
# For Example (strings scrumbled)
#
#  $myusername = 7e0c2017-a277-4baf-8c12-060f524b2329@microsoft.com 
#  $myappPassword = 199d01xx3??skf1##
#
# ARTICLE: 
#
#  Use Azure PowerShell to create a service principal to access resources
#  https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-authenticate-service-principal

# Now you can login using that credential object you created above, no more interactive logon is necessary:

Login-AzureRmAccount -Credential $mycredential -ServicePrincipal –TenantId $tenant -SubscriptionName $mySubName

#endregion 
#region Get Access Token #
#
# Setting variables values for ApplicationID and Application Key Secret 
#
$tennantid        = $tenant
$SubscriptionId   = $mySubID
$ApplicationID    = $myapp1.ApplicationId
$ApplicationKey   = 'My Application Key'
$TokenEndpoint = {https://login.windows.net/{0}/oauth2/token} -f $tennantid 
$ARMResource = "https://management.core.windows.net/";

$Body = @{
        'resource'= $ARMResource
        'client_id' = $ApplicationID
        'grant_type' = 'client_credentials'
        'client_secret' = $ApplicationKey
}

$params = @{
    ContentType = 'application/x-www-form-urlencoded'
    Headers = @{'accept'='application/json'}
    Body = $Body
    Method = 'Post'
    URI = $TokenEndpoint
}

$token = Invoke-RestMethod @params
# Show the raw token and expiration date converted in readable format: #
$token | select *, @{L='Expires';E={[timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($_.expires_on))}} | fl *

#endregion
#region SAMPLE[1]: Get Azure Subscription details: #
$baseURI = "https://management.azure.com"
$suffixURI =  "?api-version=2016-09-01"
$SubscriptionURI = $baseURI + "/subscriptions/$SubscriptionID" + $suffixURI
$uri = $SubscriptionURI
$params = @{
    ContentType = 'application/x-www-form-urlencoded'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Get'
    URI = $uri
}

$response = Invoke-RestMethod @params
$response | convertto-json 
#endregion
#region SAMPLE[2]: First look at Resource Group resource: #
(Get-AzureRmResourceGroup -Name $rgname).ResourceId #
$uri = $baseURI + ((Get-AzureRmResourceGroup -Name $rgname).ResourceId) + $suffixURI
$params = @{
    ContentType = 'application/x-www-form-urlencoded'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Get'
    URI = $uri
}
$response = Invoke-RestMethod @params
$response | convertto-json 
#endregion 
#region SAMPLE[3]: List Storage Accounts in a specific Resource Group #

# how to obtain REST artifacts from PowerShell using - Debug switch #
Get-AzureRmStorageAccount -ResourceGroupName $rgname -Debug

$suffixURI =  "?api-version=2016-12-01"
$uri = $baseURI + ((Get-AzureRmResourceGroup -Name $rgname).ResourceId) + "/providers/Microsoft.Storage/storageAccounts" + $suffixURI
$params = @{
    ContentType = 'application/x-www-form-urlencoded'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Get'
    URI = $uri
}
$response = Invoke-RestMethod @params
$response | convertto-json
#endregion 
#region SAMPLE[4]: Create a storage account #

# Status Code
# This is a long running operation, so the immediate status code will be 201. 
# You can poll for the status using the operation. (Both the Location and Azure-AsyncOperation headers are provided for this purpose.) 
# If successful, the operation returns HTTP status code of 200 (OK).

########## Create a Storage account ##########
# REST API reference here: https://docs.microsoft.com/en-us/rest/api/storagerp/storageaccounts

$storageacccountname = "Your Azure Storage Account Name"
$storagetype = "Standard_LRS"
$rgname = "Your Azure Resource Group Name" 
$location = "Your Azure Region"

# OPTIONAL Execute this cmdlet only if you want to see the underlyng generated HTTP REST call: #
#         New-AzureRmStorageAccount -Name $storageacccountname -ResourceGroupName $rgname  -Type $storagetype -Location $location -Debug

$suffixURI =  "?api-version=2016-12-01"
$baseURI = "https://management.azure.com"
$uri = $baseURI + ((Get-AzureRmResourceGroup -Name $rgname).ResourceId) + "/providers/Microsoft.Storage/storageAccounts/" `
        + "$storageacccountname" + $suffixURI

$BodyString = "{ `
   'sku': {
    'name': '" + $storagetype + "' `
  }, `
  'location': '" + $location + "' `
               }"
$params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Body = $BodyString
    Method = 'Put'
    URI = $uri
}

$response2 = Invoke-WebRequest @params 

# With "Invoke-RestMethod" there is no answer returned to check for StatusCode
# $response = Invoke-RestMethod @params 
# $response | convertto-json
# Let's try Invoke-WebRequest instead: #

$response2.StatusCode # -> 202 
$response2.StatusDescription # -> Accepted
$response2.Headers["Retry-After"] # 17 seconds in this case
$response2.Headers["x-ms-request-id"] # OperationID to check for completion
$response2.Headers["Location"] # URL to poll already including the OperationID
$response2.Headers["Date"] # START date/time of the operation
$response2.BaseResponse.Headers

# Now let's check for the completion of the above operation: #

if (!($URIAsyncCheck = $response2.Headers["Location"])) 
   {
     $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"];
     Write-Host ("Response URL returned inside [Azure-AsyncOperation] attribute") -ForegroundColor Yellow;
   } else 
     { 
       $URIAsyncCheck = $response2.Headers["Location"];
       Write-Host ("Response URL returned inside [Location] attribute") -ForegroundColor Green;
     }
 Write-Host ($URIAsyncCheck)


# NOTE: 
# The asynchronous REST operations return header values, which you use to determine the status of the operation. There are potentially three header values to examine:
#
# Azure-AsyncOperation - URL for checking the ongoing status of the operation. If your operation returns this value, always use it (instead of Location) to track the status of the operation.
# Location - URL for determining when an operation has completed. Use this value only when Azure-AsyncOperation is not returned.
# Retry-After - The number of seconds to wait before checking the status of the asynchronous operation.
# However, not every asynchronous operation returns all these values. 

# Now let's use value of $URIAsyncCheck to check the async operation status: #
$params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Get'
    URI = $URIAsyncCheck 
}
$response3 = Invoke-WebRequest @params 
$response3.StatusCode
$response3.StatusDescription

While ($response3.StatusCode -ne 200) 
 {
   Start-Sleep -s 1;
   $response3 = Invoke-WebRequest @params 
   Write-Host ("...Response Code = " + $response3.StatusCode + " ...Content Length " + $response3.RawContentLength)
 }

# Search for the "ProvisioningState" attribute in the text blob: #
if (($response3.Content.Contains('"provisioningState":"Succeeded"')))
    { Write-Host '["provisioningState":"Succeeded"] found in the Response Content payload....' -ForegroundColor Green }

if (($response3.Content.Contains('"provisioningState":"Failed"')))
    { Write-Host '["provisioningState":"Failed"] found in the Response Content payload....' -ForegroundColor Red }

if (($response3.Content.Contains('"provisioningState":"Canceled"')))
    { Write-Host '["provisioningState":"Failed"] found in the Response Content payload....' -ForegroundColor Yellow }

#endregion 
#region SAMPLE[5]: Delete storage account #

# It is a SYNC operation, as documented here: https://docs.microsoft.com/en-us/rest/api/storagerp/storageaccounts 

$storageacccountname = "Your Azure Storage Account Name"
$storagetype = "Standard_LRS" # Possible Values = "Standard_LRS,Standard_ZRS,Standard_GRS,Standard_RAGRS,Premium_LRS"
$rgname = "Your Azure Resource Group Name" 
$location = "Your Azure Region"

# Execute this only if you want to see the underlyng generated HTTP REST call #
# New-AzureRmStorageAccount -Name $storageacccountname -ResourceGroupName $rgname  -Type $storagetype -Location $location -Debug

$suffixURI =  "?api-version=2016-12-01"
$baseURI = "https://management.azure.com"
$uri = $baseURI + ((Get-AzureRmResourceGroup -Name $rgname).ResourceId) + "/providers/Microsoft.Storage/storageAccounts/" + "$storageacccountname" + $suffixURI

$BodyString = "{ `
   'sku': {
    'name': '" + $storagetype + "' `
  }, `
  'location': '" + $location + "' `
               }"
$params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Body = $BodyString
    Method = 'Delete'      
    URI = $uri
}
# Only "Method" string is changed here to DELETE #

try { $response2 = Invoke-WebRequest @params }
catch { 
        Write-Host ("Error in the HTTP request...") -ForegroundColor Red
        Break;
       }
$response2.StatusCode 
$response2.StatusDescription
$response2.Headers["Retry-After"] 
$response2.Headers["x-ms-request-id"]
$response2.Headers["Location"] 
$response2.Headers["Date"] 

# Now let's check for the completion of the above operation: #
switch ($response2.StatusCode) 
    { 
        200 {$output = "Status returned -> 200, then SYNC operation....." } 
        201 {$output = "Status returned -> 201, then ASYNC operation....."} 
        202 {$output = "Status returned -> 202, then ASYNC operation....."} 
        default {$output = "Status returned -> $response2.StatusCode"}
    }
Write-Host $output -ForegroundColor Green

# Status codes for asynchronous operations
# An asynchronous operation initially returns an HTTP status code of either:
#
# 201 (Created)
# 202 (Accepted) 
#
# When the operation successfully completes, it returns either:
#
# 200 (OK)
# 204 (No Content) 
#
if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    Write-Host ("WARNING: Response with [Azure-AsyncOperation] returned instead of [Location]") -ForegroundColor Yellow
 } 
 # NOTE: 
 # The asynchronous REST operations return header values, which you use to determine the status of the operation. There are potentially three header values to examine:
 #
 # Azure-AsyncOperation - URL for checking the ongoing status of the operation. If your operation returns this value, always use it (instead of Location) to track the status of the operation.
 # Location - URL for determining when an operation has completed. Use this value only when Azure-AsyncOperation is not returned.
 # Retry-After - The number of seconds to wait before checking the status of the asynchronous operation.
 #
 # However, not every asynchronous operation returns all these values. 

 $params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Get'
    URI = $URIAsyncCheck 
 }
 $response3 = Invoke-WebRequest @params 
 $response3.StatusCode
 $response3.StatusDescription

 While ($response3.StatusCode -ne 200) 
  {
    Start-Sleep -s 1;
    $response3 = Invoke-WebRequest @params 
    Write-Host ("...Response Code = " + $response3.StatusCode + " ...Content Length " + $response3.RawContentLength)
  }

 # Search for the "ProvisioningState" attribute in the text blob: #
  if (($response3.Content.Contains('"provisioningState":"Succeeded"')))
    { Write-Host '["provisioningState":"Succeeded"] found in the Response Content payload....' -ForegroundColor Green }
  if (($response3.Content.Contains('"provisioningState":"Failed"')))
    { Write-Host '["provisioningState":"Failed"] found in the Response Content payload....' -ForegroundColor Red }
  if (($response3.Content.Contains('"provisioningState":"Canceled"')))
    { Write-Host '["provisioningState":"Failed"] found in the Response Content payload....' -ForegroundColor Yellow }
} else { Write-Host "SYNC Operation, then no long running status check for completion...." -ForegroundColor Green }

#endregion 
#region SAMPLE[6]: Create a storage account and check long-running operation #

# Enhancements: (1) usage of StopWatch (2) polling cycle for long-running operation completion #

###### Timing with StopWatch ######
#
# EXMAPLE:
# [System.Reflection.Assembly]::LoadWithPartialName(“System.Diagnostics”) 
# $timer = new-object system.diagnostics.stopwatch
#..... DO SOMETHING.....#
# $timer.Stop()
# write-host "Operation completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds"

# Execute the line below only 1 time: #
[System.Reflection.Assembly]::LoadWithPartialName(“System.Diagnostics”) 
$timer = new-object system.diagnostics.stopwatch

# Init #
$storageacccountname = "Your Storage Account Name"
$storagetype = "Standard_LRS"
$rgname = "Your Azure Resource Group Name" 
$location = "Your Azure Region"

# Execute this only if you want to see the underlyng generated HTTP REST call #
# New-AzureRmStorageAccount -Name $storageacccountname -ResourceGroupName $rgname  -Type $storagetype -Location $location -Debug

$suffixURI =  "?api-version=2016-12-01"
$baseURI = "https://management.azure.com"
$uri = $baseURI + ((Get-AzureRmResourceGroup -Name $rgname).ResourceId) + "/providers/Microsoft.Storage/storageAccounts/" + $storageacccountname + $suffixURI

$BodyString = "{ `
   'sku': {
    'name': '" + $storagetype + "' `
  }, `
  'location': '" + $location + "' `
               }"
$params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Body = $BodyString
    Method = 'Put'      
    URI = $uri
}
# Start the timer 
$timer.Start()

# Execute the HTTP REST call #
try { $response2 = Invoke-WebRequest @params }
catch { 
        Write-Host ("Error in the HTTP request...") -ForegroundColor Red
        Break;
       }
$timer.Stop()
write-host "Step (1) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
$timer.Start()

Write-Host ("status Code = " + $response2.StatusCode + ", Description = " + $response2.StatusDescription) # status Code = 200, Description = OK

# Now let's check for the completion of the above operation: #
switch ($response2.StatusCode) 
    { 
        200 {$output = "Status returned -> 200, then SYNC operation....." } 
        201 {$output = "Status returned -> 201, then ASYNC operation....."} 
        202 {$output = "Status returned -> 202, then ASYNC operation....."} 
        default {$output = "Status returned -> $response2.StatusCode"}
    }
Write-Host $output -ForegroundColor Green

# If long-running operation, retrieve the URL to check for completion #
if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    Write-Host ("WARNING: Response with [Azure-AsyncOperation] returned instead of [Location]") -ForegroundColor Yellow
 }

 $params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Get'
    URI = $URIAsyncCheck 
 }
 $response3 = Invoke-WebRequest @params 

$timer.Stop()
write-host "Step (1+2) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
$timer.Start()

  # Stay in the loop until StatusCode will not be 200, sleep 1 second in each loop #
While ($response3.StatusCode -ne 200) 
 {
   Start-Sleep -s 1;
   $response3 = Invoke-WebRequest @params 
   Write-Host ("...Response Code = " + $response3.StatusCode + " ...Content Length " + $response3.RawContentLength)
 }
 Write-Host ("Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green
   # Search for the "ProvisioningState" attribute in the text blob: #
  if (($response3.Content.Contains('"provisioningState":"Succeeded"')))
    { Write-Host '["provisioningState":"Succeeded"] found in the Response Content payload....' -ForegroundColor Green }
  if (($response3.Content.Contains('"provisioningState":"Failed"')))
    { Write-Host '["provisioningState":"Failed"] found in the Response Content payload....' -ForegroundColor Red }
  if (($response3.Content.Contains('"provisioningState":"Canceled"')))
    { Write-Host '["provisioningState":"Failed"] found in the Response Content payload....' -ForegroundColor Yellow }

} else { Write-Host "SYNC Operation, then no long running status check for completion...." -ForegroundColor Green }

$timer.Stop()
write-host "Step (1+2+3) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 

#endregion
#region SAMPLE[7]: Create an Instance Level Public IP (PIP) and sync/async operation #

# Public IP Addresses reference: https://msdn.microsoft.com/en-us/library/azure/mt163638.aspx
# Create or update Public IP: https://msdn.microsoft.com/en-us/library/azure/mt163590.aspx

# Init #
[System.Reflection.Assembly]::LoadWithPartialName(“System.Diagnostics”) 
$timer = new-object system.diagnostics.stopwatch
$publicIPaddressname = "Your Azure Public IP Address Name"
$domainNameLabel = $publicIPaddressname
$rgname = "Your Azure Resource Group Name" 
$location = "Your Azure Region"
$publicIPAllocationMethod = "Static"
$publicIPAddressVersion = "IPv4"
$dleTimeoutInMinutes = 4

# Execute the line below only if you want to see the underling REST call: #
# New-AzureRmPublicIpAddress -Name $publicIPaddressname -ResourceGroupName $rgname -AllocationMethod Static -DomainNameLabel $dnsPrefix -Location $location -Debug

$suffixURI =  "?api-version=2016-03-30" # as per https://msdn.microsoft.com/en-us/library/azure/mt163638.aspx
$baseURI = "https://management.azure.com"
$uri = $baseURI + ((Get-AzureRmResourceGroup -Name $rgname).ResourceId) + "/providers/Microsoft.Network/publicIPAddresses/" + $publicIPaddressname + $suffixURI

$BodyString = "{ `
   'location': '" + $location + "', `
   'properties': { `
      'publicIPAllocationMethod': '" + $publicIPAllocationMethod + "', `
      'publicIPAddressVersion': '" + $publicIPAddressVersion + "', `
      'idleTimeoutInMinutes':" + $dleTimeoutInMinutes + ", `
      'dnsSettings': { `
         'domainNameLabel': '" + $domainNameLabel + "' `
        } `
   } `
}"


$params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Body = $BodyString
    Method = 'Put'      
    URI = $uri
}
# Start the timer 
$timer.Start()

# Execute the HTTP REST call #
try { $response2 = Invoke-WebRequest @params }
catch { 
        Write-Host ("Error in the HTTP request...") -ForegroundColor Red
        Break;
       }
$timer.Stop()
write-host "Step (1) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
$timer.Start()

Write-Host ("status Code = " + $response2.StatusCode + ", Description = " + $response2.StatusDescription) # returned 201 - Created

# Now let's check for the completion of the above operation: #
switch ($response2.StatusCode) 
    { 
        200 {$output = "Status returned -> 200, then SYNC operation....." } 
        201 {$output = "Status returned -> 201, then ASYNC operation....."} 
        202 {$output = "Status returned -> 202, then ASYNC operation....."} 
        default {$output = "Status returned -> $response2.StatusCode"}
    }
Write-Host $output -ForegroundColor Green

# If long-running operation, retrieve the URL to check for completion #
if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    Write-Host ("WARNING: Response with [Azure-AsyncOperation] returned instead of [Location]") -ForegroundColor Yellow
 }
 # WARNING: Response with [Azure-AsyncOperation] returned instead of [Location]

 $params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Get'
    URI = $URIAsyncCheck 
 }
 $response3 = Invoke-WebRequest @params 
 $response3.StatusCode
 $response3.StatusDescription
 
$timer.Stop()
write-host "Step (1+2) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
$timer.Start()

While (($response3.StatusCode -ne 200) -or ($response3.Content.Contains("InProgress")))
 {
   Start-Sleep -s 1;
   $response3 = Invoke-WebRequest @params 
   Write-Host ("...Response Code = " + $response3.StatusCode + " ...Content Length " + $response3.RawContentLength)
   $response3.Content
 }
 Write-Host ("Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green
 # Search for the "ProvisioningState" attribute in the text blob: #
  if (($response3.Content.Contains('"provisioningState":"Succeeded"')))
    { Write-Host '["provisioningState":"Succeeded"] found in the Response Content payload....' -ForegroundColor Green }
  if (($response3.Content.Contains('"provisioningState":"Failed"')))
    { Write-Host '["provisioningState":"Failed"] found in the Response Content payload....' -ForegroundColor Red }
  if (($response3.Content.Contains('"provisioningState":"Canceled"')))
    { Write-Host '["provisioningState":"Failed"] found in the Response Content payload....' -ForegroundColor Yellow }
} else { Write-Host "SYNC Operation, then no long running status check for completion...." -ForegroundColor Green }

$timer.Stop()
write-host "Step (1+2+3) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 

#endregion
#region SAMPLE[8]: Create a Virtual Network with a single Subnet # 
#
# Create or update a virtual network: https://msdn.microsoft.com/en-us/library/azure/mt163661.aspx

# Execute the line below only 1 time: #
[System.Reflection.Assembly]::LoadWithPartialName(“System.Diagnostics”) 

# Init #
$timer = new-object system.diagnostics.stopwatch
$rgname = "Your Azure Resource Group Name" 
$location = "Your Azure Region"
$virtualnetworkName = "You Azure VNET name"
$addressSpace = '10.1.0.0/16'
$subnetname = 'Your Subnet Name'
$subnetprefix = '10.1.0.0/24'
$dns1 = '10.1.0.5'
$dns2 = '10.1.0.6'
# Execute the line below only if you want to see the underling REST call: #
# New-AzureRmPublicIpAddress -Name $publicIPaddressname -ResourceGroupName $rgname -AllocationMethod Static -DomainNameLabel $dnsPrefix -Location $location -Debug

$suffixURI =  "?api-version=2016-03-30" 
$baseURI = "https://management.azure.com"
$uri = $baseURI + ((Get-AzureRmResourceGroup -Name $rgname).ResourceId) + "/providers/Microsoft.Network/virtualNetworks/" + $virtualnetworkName + $suffixURI

$BodyString = "{  
      'location':'"+ $location +"',
      'properties':{  
         'addressSpace':{  
            'addressPrefixes':[  
               '"+ $addressSpace + "'
            ]
         },
         'dhcpOptions':{  
            'dnsServers':[  
               '" + $dns1 + "',
               '" + $dns2 + "'
            ]
         },
         'subnets':[  
            {  
               'name':'"+ $subnetname +"',
               'properties':{  
                  'addressPrefix':'"+ $subnetprefix + "'
               }
            }
         ]
      }
   }
"


$params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Body = $BodyString
    Method = 'Put'      
    URI = $uri
}
# Start the timer 
$timer.Start()

# Execute the HTTP REST call #
try { $response2 = Invoke-WebRequest @params }
catch { 
        Write-Host ("Error in the HTTP request...") -ForegroundColor Red
        Break;
       }
$timer.Stop()
write-host "Step (1) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
$timer.Start()

Write-Host ("status Code = " + $response2.StatusCode + ", Description = " + $response2.StatusDescription) # returned 201 - Created"

# Now let's check for the completion of the above operation: #
switch ($response2.StatusCode) 
    { 
        200 {$output = "Status returned -> 200, then SYNC operation....." } 
        201 {$output = "Status returned -> 201, then ASYNC operation....."} 
        202 {$output = "Status returned -> 202, then ASYNC operation....."} 
        default {$output = "Status returned -> $response2.StatusCode"}
    }
Write-Host $output -ForegroundColor Green

# If long-running operation, retrieve the URL to check for completion #
if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    Write-Host ("WARNING: Response with [Azure-AsyncOperation] returned instead of [Location]") -ForegroundColor Yellow
 }

 $params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Get'
    URI = $URIAsyncCheck 
 }
 $response3 = Invoke-WebRequest @params 
 $response3.StatusCode
 $response3.StatusDescription
 
$timer.Stop()
write-host "Step (1+2) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
$timer.Start()

While (($response3.StatusCode -ne 200) -or ($response3.Content.Contains("InProgress")))
 {
   Start-Sleep -s 1;
   $response3 = Invoke-WebRequest @params 
   Write-Host ("...Response Code = " + $response3.StatusCode + " ...Content Length " + $response3.RawContentLength)
   $response3.Content
 }
 Write-Host ("Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green
 # Search for the "ProvisioningState" attribute in the text blob: #
  if (($response3.Content.Contains('Succeeded')))
    { Write-Host '["status":"Succeeded"] found in the Response Content payload....' -ForegroundColor Green }
  if (($response3.Content.Contains('Failed')))
    { Write-Host '["status":"Failed"] found in the Response Content payload....' -ForegroundColor Yellow }

} else { Write-Host "SYNC Operation, then no long running status check for completion...." -ForegroundColor Green }

$timer.Stop()
write-host "Step (1+2+3) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 

#endregion
#region SAMPLE[9]: Create a Network Interface Card (NIC) # 
#
# Create or update a virtual network: https://msdn.microsoft.com/en-us/library/azure/mt163661.aspx

# Init #
[System.Reflection.Assembly]::LoadWithPartialName(“System.Diagnostics”) 
$timer = new-object system.diagnostics.stopwatch
$mySubID = 'Your Azure Subscription ID' 
$rgname = "Your Azure Resource Group Name" 
$location = "Your Azure region"
$virtualnetworkName = "Your Azure VNET name"
$subnetname = 'Your Azure Subnet Name'
$subnetprefix = '10.1.0.0/24'
$NICName = 'mynic1'
$ipConfiguration = 'myip1'
$dns1 = '10.1.0.5'
$dns2 = '10.1.0.6'
$privateIPAddress = '10.1.0.8'
$privateIPAllocationMethod = 'Static'
$publicIPaddressname = "Your Public IP Address Name"
$internalDnsNameLabel = "Your internal DNS suffix"
$enableIPForwarding = 'false'

# Execute the line below only if you want to see the underling REST call: #
#
# New-AzureRmNetworkInterface -Name NetworkInterface1 -ResouceGroupName ResourceGroup1 -Location centralus -SubnetId `
#  "/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/ResourceGroup1/providers/Microsoft.Network/virtualNetworks/VirtualNetwork1/subnets/Subnet1" `
# -IpConfigurationName IPConfiguration1 -DnsServer "8.8.8.8", "8.8.4.4" -Debug
#
$suffixURI =  "?api-version=2016-03-30" 
$baseURI = "https://management.azure.com"
$uri = $baseURI + ((Get-AzureRmResourceGroup -Name $rgname).ResourceId) + "/providers/Microsoft.Network/networkInterfaces/" + $NICName + $suffixURI

$BodyString = "{  
   'location':'" + $location + "',
   'properties':{  
      'ipConfigurations':[  
         {  
            'name':'" + $ipConfiguration + "',
            'properties':{  
               'subnet':{  
                  'id':'/subscriptions/" + $mySubID + "/resourceGroups/" + $rgname + "/providers/Microsoft.Network/virtualNetworks/" + $virtualnetworkName + "/subnets/" + $subnetname + "'
               },
               'privateIPAddress':'" + $privateIPAddress + "',
               'privateIPAllocationMethod':'" + $privateIPAllocationMethod + "',
               'privateIPAddressVersion':'IPv4',
               'publicIPAddress':{  
                  'id':'/subscriptions/" + $mySubID + "/resourceGroups/" + $rgname + "/providers/Microsoft.Network/publicIPAddresses/" + $publicIPaddressname + "'
               }
            }
         }
      ],
      'dnsSettings':{  
         'dnsServers':[  
            '10.1.0.4',
            '10.1.0.5'
         ],
         'internalDnsNameLabel': '" + $internalDnsNameLabel + "'
      },
      'enableIPForwarding': '" + $enableIPForwarding + "'
   }
}
"

$params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Body = $BodyString
    Method = 'Put'      
    URI = $uri
}
# Start the timer 
$timer.Start()

# Execute the HTTP REST call #
try { $response2 = Invoke-WebRequest @params }
catch { 
        Write-Host ("Error in the HTTP request...") -ForegroundColor Red
        Break;
       }
$timer.Stop()
write-host "Step (1) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
$timer.Start()

Write-Host ("status Code = " + $response2.StatusCode + ", Description = " + $response2.StatusDescription) # returned 201 - "Created"

# Now let's check for the completion of the above operation: #
switch ($response2.StatusCode) 
    { 
        200 {$output = "Status returned -> 200, then SYNC operation....." } 
        201 {$output = "Status returned -> 201, then ASYNC operation....."} 
        202 {$output = "Status returned -> 202, then ASYNC operation....."} 
        default {$output = "Status returned -> $response2.StatusCode"}
    }
Write-Host $output -ForegroundColor Green

# If long-running operation, retrieve the URL to check for completion #
if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    Write-Host ("WARNING: Response with [Azure-AsyncOperation] returned instead of [Location]") -ForegroundColor Yellow
 }
 # WARNING: Response with [Azure-AsyncOperation] returned instead of [Location]

 $params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Get'
    URI = $URIAsyncCheck 
 }
 $response3 = Invoke-WebRequest @params 
 $response3.StatusCode
 $response3.StatusDescription
 
$timer.Stop()
write-host "Step (1+2) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
$timer.Start()

While (($response3.StatusCode -ne 200) -or ($response3.Content.Contains("InProgress")))
 {
   Start-Sleep -s 1;
   $response3 = Invoke-WebRequest @params 
   Write-Host ("...Response Code = " + $response3.StatusCode + " ...Content Length " + $response3.RawContentLength)
   $response3.Content
 }
 Write-Host ("Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green
  # Search for the "ProvisioningState" attribute in the text blob: #
  if (($response3.Content.Contains('Succeeded')))
    { Write-Host '["status":"Succeeded"] found in the Response Content payload....' -ForegroundColor Green }
  if (($response3.Content.Contains('Failed')))
    { Write-Host '["status":"Failed"] found in the Response Content payload....' -ForegroundColor Yellow }
} else { Write-Host "SYNC Operation, then no long running status check for completion...." -ForegroundColor Green }

$timer.Stop()
write-host "Step (1+2+3) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 

#endregion
#region SAMPLE[10]: Create a Network Security Group (NSG) #
#
# Azure Network REST API Reference: https://msdn.microsoft.com/en-us/library/azure/mt163658.aspx
# Network Security Groups: https://msdn.microsoft.com/en-us/library/azure/mt163615.aspx
#
# Execute the line below only 1 time: #
[System.Reflection.Assembly]::LoadWithPartialName(“System.Diagnostics”) 

# Init #
$timer = new-object system.diagnostics.stopwatch
$mySubID = 'Your Azure Subscription ID'
$rgname = "Your Azure Resource Group Name" 
$location = "Your Azure Region"
$nsgname = 'Your Azure NSG Name'
$virtualnetworkName = "Your Azure VNET Name"
$subnetname = 'Your Azure Subnet Name'
$subnetprefix = '10.1.0.0/24'

# Create NSG and rules using PowerShell cmdlet, then use REST API to "bind" to a specific subnet: #
#
# EXAMPLE: 
# Step:1 Create a security rule allowing access from the Internet to port 3389.
# Step:2 Create a security rule allowing access from the Internet to port 22.
# Step:3 Create a security rule allowing access from the Internet to port 80.
# Step:4 Add the rules created above to a new NSG named NSG-FrontEnd.

# Now let's try to create a NSG rule config:
New-AzureRmNetworkSecurityRuleConfig -Name "web-rule" -Description "Allow HTTP" -Access Allow -Protocol Tcp -Direction Inbound -Priority 102 -SourceAddressPrefix Internet -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 80

New-AzureRmNetworkSecurityRuleConfig -Name "web-rule" -Description "Allow HTTP" -Access Allow -Protocol Tcp -Direction Inbound -Priority 102 -SourceAddressPrefix Internet -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 80

# Now create real NSG rules and NSG object: #
$rule1 = New-AzureRmNetworkSecurityRuleConfig -Name "rdp-rule" -Description "Allow RDP" -Access Allow -Protocol Tcp -Direction Inbound -Priority 100 -SourceAddressPrefix Internet -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 3389
$rule2 = New-AzureRmNetworkSecurityRuleConfig -Name "ssh-rule" -Description "Allow SSH" -Access Allow -Protocol Tcp -Direction Inbound -Priority 101 -SourceAddressPrefix Internet -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 22
$rule3 = New-AzureRmNetworkSecurityRuleConfig -Name "web-rule" -Description "Allow HTTP" -Access Allow -Protocol Tcp -Direction Inbound -Priority 102 -SourceAddressPrefix Internet -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 80

New-AzureRmNetworkSecurityGroup -ResourceGroupName $rgname -Location $location -Name $nsgname -SecurityRules $rule1,$rule2,$rule3

$nsg = Get-AzureRmNetworkSecurityGroup -Name  $nsgname -ResourceGroupName $rgname

$suffixURI =  "?api-version=2016-03-30" 
$baseURI = "https://management.azure.com"
$uri = $baseURI + ((Get-AzureRmResourceGroup -Name $rgname).ResourceId) + "/providers/Microsoft.Network/virtualNetworks/" `
        + $virtualnetworkName + "/subnets/" + $subnetname +"/"+ $suffixURI

# NOTE: as you can see from https://msdn.microsoft.com/en-us/library/azure/mt163621.aspx, only NSG and UDR can be modified for a subnet #

$BodyString = "{ 
   'properties':{ 
      'addressPrefix':'" + $subnetprefix + "',
      'networkSecurityGroup':{ 
         'id':'/subscriptions/" + $mySubID + "/resourceGroups/" + $rgname + "/providers/Microsoft.Network/networkSecurityGroups/" + $nsgname + "'
      }
   }
}"

$params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Body = $BodyString
    Method = 'Put'      
    URI = $uri
}
# Start the timer 
$timer.Start()

# Execute the HTTP REST call #
try { $response2 = Invoke-WebRequest $params }
catch { 
        Write-Host ("Error in the HTTP request...") -ForegroundColor Red
        Break;
       }
$timer.Stop()
write-host "Step (1) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
$timer.Start()

Write-Host ("status Code = " + $response2.StatusCode + ", Description = " + $response2.StatusDescription) # returned 200 - "OK"

# Now let's check for the completion of the above operation: #
switch ($response2.StatusCode) 
    { 
        200 {$output = "Status returned -> 200, then SYNC operation....." } 
        201 {$output = "Status returned -> 201, then ASYNC operation....."} 
        202 {$output = "Status returned -> 202, then ASYNC operation....."} 
        default {$output = "Status returned -> $response2.StatusCode"}
    }
Write-Host $output -ForegroundColor Green # Status returned -> 200, then SYNC operation.....

# If long-running operation, retrieve the URL to check for completion #
if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    Write-Host ("WARNING: Response with [Azure-AsyncOperation] returned instead of [Location]") -ForegroundColor Yellow
 }

 $params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Get'
    URI = $URIAsyncCheck 
 }
 $response3 = Invoke-WebRequest @params 
 $response3.StatusCode
 $response3.StatusDescription

$timer.Stop()
write-host "Step (1+2) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
$timer.Start()

  # Stay in the loop until StatusCode will not be 200, sleep 1 second in each loop #
While (($response3.StatusCode -ne 200) -or ($response3.Content.Contains("InProgress")))
 {
   Start-Sleep -s 1;
   $response3 = Invoke-WebRequest @params 
   Write-Host ("...Response Code = " + $response3.StatusCode + " ...Content Length " + $response3.RawContentLength)
   $response3.Content
 }
 Write-Host ("Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green
  # Search for the "ProvisioningState" attribute in the text blob: #
  if (($response3.Content.Contains('Succeeded')))
    { Write-Host '["status":"Succeeded"] found in the Response Content payload....' -ForegroundColor Green }
  if (($response3.Content.Contains('Failed')))
    { Write-Host '["status":"Failed"] found in the Response Content payload....' -ForegroundColor Yellow }
} else { Write-Host "SYNC Operation, then no long running status check for completion...." -ForegroundColor Green }

$timer.Stop()
write-host "Step (1+2+3) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 

#endregion
#region SAMPLE[11]: Create a Standard Availability Set (AS) #
#
# Availability Set: https://docs.microsoft.com/en-us/rest/api/compute/availabilitysets
#
# NOTE: This is a standad Availability Set, not a MANAGED one!

# Init #
[System.Reflection.Assembly]::LoadWithPartialName(“System.Diagnostics”) 
$timer = new-object system.diagnostics.stopwatch
$rgname = "Your Azure Resource Group Name" 
$asname = "Your Azure Availability Set Name" 
$location = "Your Azure Region"
$platformUpdateDomainCount = 20
$platformFaultDomainCount = 3

# Execute the line below only if you want to see the underling REST call: #
#
# New-AzureRmAvailabilitySet -ResourceGroupName $rgname -Name $asname -Location $location -Debug
#
# Let's use it since in the documentation on https://docs.microsoft.com/en-us/rest/api/compute/availabilitysets there is n BODY shown: #
#
# New-AzureRmAvailabilitySet -ResourceGroupName $rgname -Name $asname -Location $location -PlatformUpdateDomainCount $platformUpdateDomainCount -PlatformFaultDomainCount $platformFaultDomainCount -Debug
# Remove-AzureRmAvailabilitySet -ResourceGroupName $rgname -Name $asname -Location $location -Debug

$suffixURI =  "?api-version=2016-03-30" 
$baseURI = "https://management.azure.com"
$uri = $baseURI + ((Get-AzureRmResourceGroup -Name $rgname).ResourceId) + "/providers/Microsoft.Compute/availabilitySets/" + $asname + $suffixURI

$BodyString = "{
  'location': '" + $location + "',
  'properties': {
    'platformUpdateDomainCount':" + $platformUpdateDomainCount + ",
    'platformFaultDomainCount':" + $platformFaultDomainCount + "
  }
}"

$params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Body = $BodyString
    Method = 'Put'      
    URI = $uri
}
# Start the timer 
$timer.Start()

# Execute the HTTP REST call #

try { $response2 = Invoke-WebRequest @params }
catch { 
        Write-Host ("Error in the HTTP request...") -ForegroundColor Red
        Break;
       }
$timer.Stop()
write-host "Step (1) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
$timer.Start()

Write-Host ("status Code = " + $response2.StatusCode + ", Description = " + $response2.StatusDescription) # returned 200 - "OK"

# Now let's check for the completion of the above operation: #
switch ($response2.StatusCode) 
    { 
        200 {$output = "Status returned -> 200, then SYNC operation....." } 
        201 {$output = "Status returned -> 201, then ASYNC operation....."} 
        202 {$output = "Status returned -> 202, then ASYNC operation....."} 
        default {$output = "Status returned -> $response2.StatusCode"}
    }
Write-Host $output -ForegroundColor Green

# If long-running operation, retrieve the URL to check for completion #
if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    Write-Host ("WARNING: Response with [Azure-AsyncOperation] returned instead of [Location]") -ForegroundColor Yellow
 }
 # WARNING: Response with [Azure-AsyncOperation] returned instead of [Location]

 $params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Get'
    URI = $URIAsyncCheck 
 }
 $response3 = Invoke-WebRequest @params 
 $response3.StatusCode
 $response3.StatusDescription
 
$timer.Stop()
write-host "Step (1+2) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
$timer.Start()

While (($response3.StatusCode -ne 200) -or ($response3.Content.Contains("InProgress")))
 {
   Start-Sleep -s 1;
   $response3 = Invoke-WebRequest @params 
   Write-Host ("...Response Code = " + $response3.StatusCode + " ...Content Length " + $response3.RawContentLength)
   $response3.Content
 }
 Write-Host ("Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green
 # Search for the "ProvisioningState" attribute in the text blob: #
  if (($response3.Content.Contains('"provisioningState":"Succeeded"')))
    { Write-Host '["provisioningState":"Succeeded"] found in the Response Content payload....' -ForegroundColor Green }
  if (($response3.Content.Contains('"provisioningState":"Failed"')))
    { Write-Host '["provisioningState":"Failed"] found in the Response Content payload....' -ForegroundColor Red }
  if (($response3.Content.Contains('"provisioningState":"Canceled"')))
    { Write-Host '["provisioningState":"Failed"] found in the Response Content payload....' -ForegroundColor Yellow }
} else { Write-Host "SYNC Operation, then no long running status check for completion...." -ForegroundColor Green }

$timer.Stop()
write-host "Step (1+2+3) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 

#endregion
#region SAMPLE[12]: Ceate Managed Availability Set (AS) #
#
# Availability Set: https://docs.microsoft.com/en-us/rest/api/compute/availabilitysets
#
# NOTE: This is a standad Availability Set, not a MANAGED one!

# Init #
[System.Reflection.Assembly]::LoadWithPartialName(“System.Diagnostics”) 
$timer = new-object system.diagnostics.stopwatch
$rgname = "Your Azure Resource Group Name" 
$asname = "Your Azure Availability Set Name" 
$location = "Your Azure Region"
$platformUpdateDomainCount = 20
$platformFaultDomainCount = 3

# Execute the line below only if you want to see the underling REST call: #
#
# New-AzureRmAvailabilitySet -ResourceGroupName $rgname -Name $asname -Location $location -PlatformUpdateDomainCount $platformUpdateDomainCount -PlatformFaultDomainCount $platformFaultDomainCount  -Managed -Debug
#
# Let's use it since in the documentation on https://docs.microsoft.com/en-us/rest/api/compute/availabilitysets there is n BODY shown: #
#
# New-AzureRmAvailabilitySet -ResourceGroupName $rgname -Name $asname -Location $location -PlatformUpdateDomainCount $platformUpdateDomainCount -PlatformFaultDomainCount $platformFaultDomainCount -Debug
# Remove-AzureRmAvailabilitySet -ResourceGroupName $rgname -Name $asname -Location $location -Debug

$suffixURI =  "?api-version=2016-04-30-preview" 
$baseURI = "https://management.azure.com"
$uri = $baseURI + ((Get-AzureRmResourceGroup -Name $rgname).ResourceId) + "/providers/Microsoft.Compute/availabilitySets/" + $asname + $suffixURI

# NOTE: note the "'managed': true" in the BODY definition #
$BodyString = "{
  'location': '" + $location + "',
  'properties': {
    'platformUpdateDomainCount':" + $platformUpdateDomainCount + ",
    'platformFaultDomainCount':" + $platformFaultDomainCount + ",
    'managed': true
  }
}"

$params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Body = $BodyString
    Method = 'Put'      
    URI = $uri
}
# Start the timer 
$timer.Start()

# Execute the HTTP REST call #

try { $response2 = Invoke-WebRequest @params }
catch { 
        Write-Host ("Error in the HTTP request...") -ForegroundColor Red
        Break;
       }
$timer.Stop()
write-host "Step (1) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
$timer.Start()

Write-Host ("status Code = " + $response2.StatusCode + ", Description = " + $response2.StatusDescription) # returned 200 - OK"

# Now let's check for the completion of the above operation: #
switch ($response2.StatusCode) 
    { 
        200 {$output = "Status returned -> 200, then SYNC operation....." } 
        201 {$output = "Status returned -> 201, then ASYNC operation....."} 
        202 {$output = "Status returned -> 202, then ASYNC operation....."} 
        default {$output = "Status returned -> $response2.StatusCode"}
    }
Write-Host $output -ForegroundColor Green

# If long-running operation, retrieve the URL to check for completion #
if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    Write-Host ("WARNING: Response with [Azure-AsyncOperation] returned instead of [Location]") -ForegroundColor Yellow
 }
 # WARNING: Response with [Azure-AsyncOperation] returned instead of [Location]

 $params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Get'
    URI = $URIAsyncCheck 
 }
 $response3 = Invoke-WebRequest @params 
 $response3.StatusCode
 $response3.StatusDescription
 
$timer.Stop()
write-host "Step (1+2) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
$timer.Start()

While (($response3.StatusCode -ne 200) -or ($response3.Content.Contains("InProgress")))
 {
   Start-Sleep -s 1;
   $response3 = Invoke-WebRequest @params 
   Write-Host ("...Response Code = " + $response3.StatusCode + " ...Content Length " + $response3.RawContentLength)
   $response3.Content
 }
 Write-Host ("Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green
 # Search for the "ProvisioningState" attribute in the text blob: #
  if (($response3.Content.Contains('"provisioningState":"Succeeded"')))
    { Write-Host '["provisioningState":"Succeeded"] found in the Response Content payload....' -ForegroundColor Green }
  if (($response3.Content.Contains('"provisioningState":"Failed"')))
    { Write-Host '["provisioningState":"Failed"] found in the Response Content payload....' -ForegroundColor Red }
  if (($response3.Content.Contains('"provisioningState":"Canceled"')))
    { Write-Host '["provisioningState":"Failed"] found in the Response Content payload....' -ForegroundColor Yellow }
} else { Write-Host "SYNC Operation, then no long running status check for completion...." -ForegroundColor Green }

$timer.Stop()
write-host "Step (1+2+3) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 

#endregion 
#region SAMPLE[13]: Create a Windows VM using previously created components # 
#
# Virtual Machines: https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines
# 
# These are all the objects you need: 
#
# Create a resource group
# Create a storage account
# Create a virtual network with a subnet
# Create a NSG
# Create a network interface
# Create a public IP address
# Create an availability set

# Execute the line below only 1 time: #
[System.Reflection.Assembly]::LoadWithPartialName(“System.Diagnostics”) 
$timer = new-object system.diagnostics.stopwatch

# Init #
$vmname = "Your Azure VM Name"
$rgname = "Your Azure Resource Group Name" 
$location = "Your Azure Region"
$virtualnetworkName = "Your Azure VNET Name"
$subnetname = 'Your Azure Subnet Name'
$nsgname = 'Your Azure NSG Name'
$subnetprefix = '10.1.0.0/24'
$publicIPaddressname = "Your Azure Public IP Address Name" 
$NICName = 'Your Azure NIC Name'
$asname = "Your Azure Availability Set Name" 
$ComputerName = $VMName
$OSDiskName = $VMName + "osDisk"
$storageacccountname = "Your Azure Storage Account Name"
$vmpwd = 'Your Azure VM Local Admin Password'
$AccountName = 'Your Azure VM Local Admin Account Name'
$VMSize = "Standard_DS2"

#################################################################################################################################################
#                                                                                                                                               #
#                        Execute the line below only if you want to see the underling REST call, otherwse skip to next section                  #
#                                                                                                                                               #
#################################################################################################################################################

########### Create the VM using pre-existing objects ##########

# Storage
$StorageAccount = Get-AzureRMStorageAccount -Name $storageacccountname -ResourceGroupName $rgname
# Networking
$vip = Get-AzureRmPublicIpAddress -Name $publicIPaddressname -ResourceGroupName $rgName
$vnet = Get-AzureRmVirtualNetwork -Name $virtualnetworkName -ResourceGroupName $rgname
$subnet = Get-AzureRmVirtualNetworkSubnetConfig -Name $subnetname -VirtualNetwork $vnet
$Interface = Get-AzureRmNetworkInterface -Name $NICName -ResourceGroupName $rgname
# Credentials
$SecurePassword = ConvertTo-SecureString $vmpwd -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ($AccountName, $SecurePassword); 
# HA
$AvailabilitySet = Get-AzureRmAvailabilitySet -ResourceGroupName $rgname -Name $asname
# VM Config
$VirtualMachine = New-AzureRmVMConfig -VMName $vmname -VMSize $VMSize -AvailabilitySetId $AvailabilitySet.Id 
# Set OS
$VirtualMachine = Set-AzureRmVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $ComputerName -Credential $Credential 
# Set Source Image
$VirtualMachine = Set-AzureRmVMSourceImage -VM $VirtualMachine -PublisherName "MicrosoftWindowsServer" -Offer "WindowsServer" -Skus "2012-R2-Datacenter" -Version "latest"
# Add NIC
$VirtualMachine = Add-AzureRmVMNetworkInterface -VM $VirtualMachine -Id $Interface.Id 
# Set OS Disk 
$OSDiskUri = $StorageAccount.PrimaryEndpoints.Blob.ToString() + "vhds/" + $OSDiskName + ".vhd"
$VirtualMachine = Set-AzureRmVMOSDisk -VM $VirtualMachine -Name $OSDiskName -VhdUri $OSDiskUri -CreateOption FromImage 

## FINALLY, create the VM
New-AzureRmVM -ResourceGroupName $rgname -Location $location -VM $VirtualMachine -Debug

#################################################################################################################################################
#                                                                                                                                               #
#                  Now repeat the same VM creation operation using REST API and BODY from the previous generated file                           #
#                                                                                                                                               #
#################################################################################################################################################

# NOTE: Different parameters have been used here to vary the configuration, but logic flow is almost the same.

# Init #
[System.Reflection.Assembly]::LoadWithPartialName(“System.Diagnostics”) 
# Init #
$vmname = "Your Azure VM Name"
$rgname = "Your Azure Resource Group Name" 
$location = "Your Azure Region"
$virtualnetworkName = "Your Azure VNET Name"
$subnetname = 'Your Azure Subnet Name'
$nsgname = 'Your Azure NSG Name'
$subnetprefix = '10.1.0.0/24'
$publicIPaddressname = "Your Azure Public IP Address Name" 
$NICName = 'Your Azure NIC Name'
$asname = "Your Azure Availability Set Name" 
$ComputerName = $VMName
$OSDiskName = $VMName + "osDisk"
$storageacccountname = "Your Azure Storage Account Name"
$vmpwd = 'Your Azure VM Local Admin Password'
$AccountName = 'Your Azure VM Local Admin Account Name'
$VMSize = "Standard_DS2"
# Select the Linux OS image #
$publisher = (Get-AzureRmVMImagePublisher -Location $location |? PublisherName -like "OpenLogic").PublisherName
$offer = (Get-AzureRmVMImageOffer -Location $location -PublisherName $publisher | ? Offer -EQ "CentOS").Offer
$sku = (Get-AzureRmVMImageSku -Location $location -Offer $offer -PublisherName $publisher | ? Skus -EQ "6.5").Skus
$imageid = (Get-AzureRmVMImage -Location $location -Offer $offer -PublisherName $publisher -Skus $sku | Sort Version -Descending)[0].Id
$version = (Get-AzureRmVMImage -Location $location -Offer $offer -PublisherName $publisher -Skus $sku | Sort Version -Descending)[0].Version
$OSDiskName = $vmname + "osDisk"
$StorageAccount = Get-AzureRMStorageAccount -Name $storageacccountname -ResourceGroupName $rgname
$OSDiskUri = $StorageAccount.PrimaryEndpoints.Blob.ToString() + "vhds/" + $OSDiskName + ".vhd"
$storageUri = $StorageAccount.PrimaryEndpoints.Blob.ToString()
$Interface = Get-AzureRmNetworkInterface -Name $NICName -ResourceGroupName $rgname
$AvailabilitySet = Get-AzureRmAvailabilitySet -ResourceGroupName $rgname -Name $asname

#### Now repeat the same VM creation operation using REST API and BODY from the previous generated file ###
$suffixURI =  "?api-version=2016-04-30-preview" 
$baseURI = "https://management.azure.com"
$uri = $baseURI + ((Get-AzureRmResourceGroup -Name $rgname).ResourceId) + "/providers/Microsoft.Compute/virtualMachines/" + $vmname + $suffixURI

# Example of "Absolute Uri" in the HTTP PUT request: #
# https://management.azure.com/subscriptions/8e95e0ss-d7ss-44ss-94ss-75ca862d34ss/resourceGroups/<resource group>/providers/Microsoft.Compute/virtualMachines/<VM name>?api-version=2016-03-30

#NOTE: There is no VHDUri for OS disk since we want to use MANAGED DISK for this. Here there is an implicit usage declaration.
$BodyString = "
{
  'properties': {
    'hardwareProfile': {
      'vmSize': '" + $VMSize + "'
    },
    'storageProfile': {
      'imageReference': {
        'publisher':'"+ $publisher + "',
        'offer': '" + $offer + "',
        'sku': '" + $sku + "',
        'version': '" + $version + "'
      },
      'osDisk': {
        'name': '" + $OSDiskName + "',
        'createOption': 'fromImage',
        'managedDisk': {
            'storageAccountType': 'Standard_LRS'
            }
      }
    },
    'osProfile': {
      'computerName': '" + $vmname + "',
      'adminUsername': '" + $AccountName +  "',
      'adminPassword': '" + $vmpwd + "',
      'linuxConfiguration': {
        'disablePasswordAuthentication': false
      },
      'secrets': []
    },
    'networkProfile': {
      'networkInterfaces': [
        {
          'id': '" + $Interface.Id + "'
        }
      ]
    },
    'diagnosticsProfile': {
      'bootDiagnostics': {
        'enabled': true,
        'storageUri': '" + $storageUri + "'
      }
    },
    'availabilitySet': {
      'id': '" + $AvailabilitySet.Id + "'
    }
  },
  'location': '" + $location + "'
}"

$params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Body = $BodyString
    Method = 'Put'      
    URI = $uri
}
# Start the timer 
$timer.Start()

# Execute the HTTP REST call #
try { $response2 = Invoke-WebRequest @params }
catch { 
        Write-Host ("Error in the HTTP request...") -ForegroundColor Red
        Break;
       }
$timer.Stop()
Write-Host ("status Code = " + $response2.StatusCode + ", Description = " + $response2.StatusDescription)
write-host "Step (1) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
$timer.Start()

Write-Host ("status Code = " + $response2.StatusCode + ", Description = " + $response2.StatusDescription) # returned 201 - Created"

# Now let's check for the completion of the above operation: #
switch ($response2.StatusCode) 
    { 
        200 {$output = "Status returned -> 200, then SYNC operation....." } 
        201 {$output = "Status returned -> 201, then ASYNC operation....."} 
        202 {$output = "Status returned -> 202, then ASYNC operation....."} 
        default {$output = "Status returned -> $response2.StatusCode"}
    }
Write-Host $output -ForegroundColor Green

# If long-running operation, retrieve the URL to check for completion #
if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    Write-Host ("WARNING: Response with [Azure-AsyncOperation] returned instead of [Location]") -ForegroundColor Yellow
 }
 # Response with [Azure-AsyncOperation] returned instead of [Location]
}

 $params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Get'
    URI = $URIAsyncCheck
 }
 $response3 = Invoke-WebRequest @params 
 $response3.StatusCode
 $response3.StatusDescription
 $response3.Content
 $response3.Content.Contains("InProgress")
 
 if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    While ($response3.Content.Contains("InProgress")) 
     {
       Start-Sleep -s 5;
       $response3 = Invoke-WebRequest @params
       Write-Host ("Checking  [Azure-AsyncOperation]...$($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds") -ForegroundColor Yellow
     }
    Write-Host ("Checking  [Azure-AsyncOperation]...Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green
 }
 
$timer.Stop()
write-host "Step (1+2) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
write-host $response3.Content
$timer.Start()

While (($response3.StatusCode -ne 200) -or ($response3.Content.Contains("InProgress")))
 {
   Start-Sleep -s 1;
   $response3 = Invoke-WebRequest @params 
   Write-Host ("...Response Code = " + $response3.StatusCode + " ...Content Length " + $response3.RawContentLength)
   $response3.Content
 }
 Write-Host ("Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green
 # Search for the "ProvisioningState" attribute in the text blob: #
  if (($response3.Content.Contains('Succeeded')))
    { Write-Host '["Status":"Succeeded"] found in the Response Content payload....' -ForegroundColor Green }
  if (($response3.Content.Contains('Failed')))
    { Write-Host '["Status":"Failed"] found in the Response Content payload....' -ForegroundColor Red }
} else { Write-Host "SYNC Operation, then no long running status check for completion...." -ForegroundColor Green }

$timer.Stop()
write-host "Step (1+2+3) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 

#endregion
#region SAMPLE[14]: Delete a VM #
#
# REST API reference: https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines#VirtualMachines_Delete
#

# Init #
[System.Reflection.Assembly]::LoadWithPartialName(“System.Diagnostics”) 
$timer = new-object system.diagnostics.stopwatch
$vmname = "Your Azure VM Name"
$rgname = "Your Azure Resource Group Name" 
$location = "West Europe"

# Build the URI: #
#
# HTTP request:
# DELETE /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}?api-version=2016-03-30
#
$suffixURI =  "?api-version=2016-03-30" 
$baseURI = "https://management.azure.com"
$uri = $baseURI + ((Get-AzureRmResourceGroup -Name $rgname).ResourceId) + "/providers/Microsoft.Compute/virtualMachines/" + $vmname + $suffixURI
# NOTE: Same URI as creation, but empty BODY and DELETE HTTP verb: #

$BodyString = ""

$params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Body = $BodyString
    Method = 'Delete'      
    URI = $uri
}

# Start the timer 
$timer.Start()
# Execute the HTTP REST call #
try { $response2 = Invoke-WebRequest @params }
catch { 
        Write-Host ("Error in the HTTP request...") -ForegroundColor Red
        Break;
       }
$timer.Stop()
write-host "Step (1) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
$timer.Start()

Write-Host ("status Code = " + $response2.StatusCode + ", Description = " + $response2.StatusDescription) # returned 202 - Accepted

# Now let's check for the completion of the above operation: #
switch ($response2.StatusCode) 
    { 
        200 {$output = "Status returned -> 200, then SYNC operation....." } 
        201 {$output = "Status returned -> 201, then ASYNC operation....."} 
        202 {$output = "Status returned -> 202, then ASYNC operation....."} 
        default {$output = "Status returned -> " + $response2.StatusCode + "..."}
    }
Write-Host $output -ForegroundColor Green

# If long-running operation, retrieve the URL to check for completion #
if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    Write-Host ("WARNING: Response with [Azure-AsyncOperation] returned instead of [Location]") -ForegroundColor Yellow
 }
 # Response with [Azure-AsyncOperation] returned instead of [Location]
}

 $params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Get'
    URI = $URIAsyncCheck
 }
 $response3 = Invoke-WebRequest @params 
 $response3.StatusCode
 $response3.StatusDescription
 $response3.Content
 $response3.Content.Contains("InProgress")
 
 if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    While ($response3.Content.Contains("InProgress")) 
     {
       Start-Sleep -s 5;
       $response3 = Invoke-WebRequest @params
       Write-Host ("Checking  [Azure-AsyncOperation]...$($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds") -ForegroundColor Yellow
     }
    Write-Host ("Checking  [Azure-AsyncOperation]...Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green
 }
 
$timer.Stop()
write-host "Step (1+2) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
write-host $response3.Content
$timer.Start()

While (($response3.StatusCode -ne 200) -or ($response3.Content.Contains("InProgress")))
 {
   Start-Sleep -s 1;
   $response3 = Invoke-WebRequest @params 
   Write-Host ("...Response Code = " + $response3.StatusCode + " ...Content Length " + $response3.RawContentLength)
   $response3.Content
 }
 Write-Host ("Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green
 # Search for the "ProvisioningState" attribute in the text blob: #
  if (($response3.Content.Contains('Succeeded')))
    { Write-Host '["Status":"Succeeded"] found in the Response Content payload....' -ForegroundColor Green }
  if (($response3.Content.Contains('Failed')))
    { Write-Host '["Status":"Failed"] found in the Response Content payload....' -ForegroundColor Red }
} else { Write-Host "SYNC Operation, then no long running status check for completion...." -ForegroundColor Green }

$timer.Stop()
write-host "Step (1+2+3) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 

#endregion
#region SAMPLE[15]: Create a Linux VM for Image capture #

# Init #
[System.Reflection.Assembly]::LoadWithPartialName(“System.Diagnostics”) 
$timer = new-object system.diagnostics.stopwatch

$vmname = 'Your Azure VM Name'
$vmpwd = 'Your Azure VM Local Admin Password'
$AccountName = 'Your Azure VM Local Admin Name'
$rgname = 'Your Azure Resource Group Name' 
$location = 'Your Azure Region'
$virtualnetworkName = 'Your Azure VNET Name'
$subnetname = 'Your Azure Subnet Name'
$nsgname = 'Your Azure NSG Name'
$subnetprefix = '10.1.0.0/24'
$publicIPaddressname = 'Your Azure Public IP Address Name'
$NICName = 'Your Azure NIC Name'
$asname = 'Your Azure Availability Set Name'
$ComputerName = $VMName
$OSDiskName = $VMName + "osDisk"
$storageacccountname = 'Your Azure Storage Account Name'
$VMSize = 'Standard_DS2'

$OSDiskName = $vmname + "osDisk"
$StorageAccount = Get-AzureRmStorageAccount -Name $storageacccountname -ResourceGroupName $rgname
$OSDiskUri = $StorageAccount.PrimaryEndpoints.Blob.ToString() + "vhds/" + $OSDiskName + ".vhd"
$storageUri = $StorageAccount.PrimaryEndpoints.Blob.ToString()
$Interface = Get-AzureRmNetworkInterface -Name $NICName -ResourceGroupName $rgname
$AvailabilitySet = Get-AzureRmAvailabilitySet -ResourceGroupName $rgname -Name $asname

# Select OS Image: #
$publisher = (Get-AzureRmVMImagePublisher -Location $location |? PublisherName -like "OpenLogic").PublisherName
$offer = (Get-AzureRmVMImageOffer -Location $location -PublisherName $publisher | ? Offer -EQ "CentOS").Offer
$sku = (Get-AzureRmVMImageSku -Location $location -Offer $offer -PublisherName $publisher | ? Skus -EQ "6.5").Skus
$imageid = (Get-AzureRmVMImage -Location $location -Offer $offer -PublisherName $publisher -Skus $sku | Sort Version -Descending)[0].Id
$version = (Get-AzureRmVMImage -Location $location -Offer $offer -PublisherName $publisher -Skus $sku | Sort Version -Descending)[0].Version

# Build URI string #
$suffixURI =  "?api-version=2016-03-30" 
$baseURI = "https://management.azure.com"
$uri = $baseURI + ((Get-AzureRmResourceGroup -Name $rgname).ResourceId) + "/providers/Microsoft.Compute/virtualMachines/" + $vmname + $suffixURI

# Example of "Absolute Uri" in the HTTP PUT request: #
# https://management.azure.com/subscriptions/8e95e0bb-d7cc-4454-9443-75ca862d34c1/resourceGroups/<Resource Group>/providers/Microsoft.Compute/virtualMachines/igortestpsvm2?api-version=2016-03-30

$BodyString = "
{
  'properties': {
    'hardwareProfile': {
      'vmSize': '" + $VMSize + "'
    },
    'storageProfile': {
      'imageReference': {
        'publisher':'"+ $publisher + "',
        'offer': '" + $offer + "',
        'sku': '" + $sku + "',
        'version': '" + $version + "'
      },
      'osDisk': {
        'name': '" + $OSDiskName + "',
        'vhd': {
          'uri': '" + $OSDiskUri + "'
        },
        'createOption': 'fromImage'
      }
    },
    'osProfile': {
      'computerName': '" + $vmname + "',
      'adminUsername': '" + $AccountName + "',
      'adminPassword': '" + $vmpwd + "',
      'linuxConfiguration': {}
    },
    'networkProfile': {
      'networkInterfaces': [
        {
          'id': '" + $Interface.Id + "'
        }
      ]
    },
    'diagnosticsProfile': {
      'bootDiagnostics': {
        'enabled': true,
        'storageUri': '" + $storageUri + "'
      }
    },
    'availabilitySet': {
      'id': '" + $AvailabilitySet.Id + "'
    }
  },
  'location': '" + $location + "'
}"

$params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Body = $BodyString
    Method = 'Put'      
    URI = $uri
}
# Start the timer 
$timer.Start()

# Execute the HTTP REST call #
try { $response2 = Invoke-WebRequest @params }
catch { 
        Write-Host ("Error in the HTTP request...") -ForegroundColor Red
        Break;
       }
$timer.Stop()
write-host "Step (1) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
$timer.Start()

Write-Host ("status Code = " + $response2.StatusCode + ", Description = " + $response2.StatusDescription) # returned 201 - Created

# Now let's check for the completion of the above operation: #
switch ($response2.StatusCode) 
    { 
        200 {$output = "Status returned -> 200, then SYNC operation....." } 
        201 {$output = "Status returned -> 201, then ASYNC operation....."} 
        202 {$output = "Status returned -> 202, then ASYNC operation....."} 
        default {$output = "Status returned -> " + $response2.StatusCode + "..."}
    }
Write-Host $output -ForegroundColor Green

# If long-running operation, retrieve the URL to check for completion #
if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    Write-Host ("WARNING: Response with [Azure-AsyncOperation] returned instead of [Location]") -ForegroundColor Yellow
 }
 # Response with [Azure-AsyncOperation] returned instead of [Location]
}

 $params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Get'
    URI = $URIAsyncCheck
 }
 $response3 = Invoke-WebRequest @params 
 $response3.StatusCode
 $response3.StatusDescription
 $response3.Content
 $response3.Content.Contains("InProgress")
 
 if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    While ($response3.Content.Contains("InProgress")) 
     {
       Start-Sleep -s 5;
       $response3 = Invoke-WebRequest @params
       Write-Host ("Checking  [Azure-AsyncOperation]...$($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds") -ForegroundColor Yellow
     }
    Write-Host ("Checking  [Azure-AsyncOperation]...Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green
 }
 
$timer.Stop()
write-host "Step (1+2) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
write-host $response3.Content
$timer.Start()

  # Stay in the loop until StatusCode will not be 200, sleep 1 second in each loop #
While (($response3.StatusCode -ne 200) -or ($response3.Content.Contains("InProgress")))
 {
   Start-Sleep -s 1;
   $response3 = Invoke-WebRequest @params 
   Write-Host ("...Response Code = " + $response3.StatusCode + " ...Content Length " + $response3.RawContentLength)
   $response3.Content
 }
 Write-Host ("Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green
 # Search for the "ProvisioningState" attribute in the text blob: #
  if (($response3.Content.Contains('Succeeded')))
    { Write-Host '["Status":"Succeeded"] found in the Response Content payload....' -ForegroundColor Green }
  if (($response3.Content.Contains('Failed')))
    { Write-Host '["Status":"Failed"] found in the Response Content payload....' -ForegroundColor Red }
} else { Write-Host "SYNC Operation, then no long running status check for completion...." -ForegroundColor Green }

$timer.Stop()
write-host "Step (1+2+3) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 

#endregion 
#region SAMPLE[16]: Stop the VM before Image capture #

# Before proceeding, the VM must be generalized following the instructions below: 
#
# (1) Capture a Linux virtual machine running on Azure (only remove the WAAgent and Stop VM: # https://docs.microsoft.com/en-us/azure/virtual-machines/virtual-machines-linux-capture-image
# (2) Stop and dealloacate the VM: https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines#VirtualMachines_Deallocate
# (3) Capture the VM image: https://docs.microsoft.com/en-us/azure/virtual-machines/virtual-machines-windows-capture-image

# Init #
[System.Reflection.Assembly]::LoadWithPartialName(“System.Diagnostics”) 
$timer = new-object system.diagnostics.stopwatch
$vmname = "Your Azure VM Name"
$rgname = "Your Azure Resource Group Name" 
$location = "Your Azure Region"

[System.Reflection.Assembly]::LoadWithPartialName(“System.Diagnostics”) 
$timer = new-object system.diagnostics.stopwatch
# Build URI string #
$suffixURI =  "?api-version=2016-03-30" 
$baseURI = "https://management.azure.com"
$uri = $baseURI + ((Get-AzureRmResourceGroup -Name $rgname).ResourceId) + "/providers/Microsoft.Compute/virtualMachines/" + $vmname + "/deallocate" + $suffixURI
# URI Example: 
# POST /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/deallocate?api-version=2016-03-30

# NOTE: There is no body here to pass #
$params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Post'      
    URI = $uri
}
# Start the timer 
$timer.Start()

# Execute the HTTP REST call #
try { $response2 = Invoke-WebRequest @params }
catch { 
        Write-Host ("Error in the HTTP request...") -ForegroundColor Red
        Break;
       }
$timer.Stop()

write-host "Step (1) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
$timer.Start()

Write-Host ("status Code = " + $response2.StatusCode + ", Description = " + $response2.StatusDescription) # returned 202 - "ACCEPTED"

# Now let's check for the completion of the above operation: #
switch ($response2.StatusCode) 
    { 
        200 {$output = "Status returned -> 200, then SYNC operation....." } 
        201 {$output = "Status returned -> 201, then ASYNC operation....."} 
        202 {$output = "Status returned -> 202, then ASYNC operation....."} 
        default {$output = "Status returned -> " + $response2.StatusCode + "..."}
    }
Write-Host $output -ForegroundColor Green

# If long-running operation, retrieve the URL to check for completion #
if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    Write-Host ("WARNING: Response with [Azure-AsyncOperation] returned instead of [Location]") -ForegroundColor Yellow
 }
 # Response with [Azure-AsyncOperation] returned instead of [Location]
}

 $params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Get'
    URI = $URIAsyncCheck
 }
 $response3 = Invoke-WebRequest @params 
 $response3.StatusCode
 $response3.StatusDescription
 $response3.Content
 $response3.Content.Contains("InProgress")
 
 if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    While ($response3.Content.Contains("InProgress")) 
     {
       Start-Sleep -s 5;
       $response3 = Invoke-WebRequest @params
       Write-Host ("Checking  [Azure-AsyncOperation]...$($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds") -ForegroundColor Yellow
     }
    Write-Host ("Checking  [Azure-AsyncOperation]...Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green
 }
 
$timer.Stop()
write-host "Step (1+2) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
write-host $response3.Content
$timer.Start()

  # Stay in the loop until StatusCode will not be 200, sleep 1 second in each loop #
While ($response3.StatusCode -ne 200) 
 {
   Start-Sleep -s 1;
   $response3 = Invoke-WebRequest @params 
   Write-Host ("Waiting for completion...$($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds") -ForegroundColor Yellow
 }
 Write-Host ("Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green

} else { Write-Host "SYNC Operation, then no long running status check for completion...." -ForegroundColor Green }

$timer.Stop()
write-host "Step (1+2+3) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 

#endregion 
#region SAMPLE[17]: VM Generalize Operation before Image CApture #
#
# https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines#VirtualMachines_Generalize 
# Build URI string #
#
[System.Reflection.Assembly]::LoadWithPartialName(“System.Diagnostics”) 
$timer = new-object system.diagnostics.stopwatch
$rgname = 'Your Azure Resource Group Name'
$vmname = "Your Azure VM Name"
$location = "Your Azure Region"
$suffixURI =  "?api-version=2016-03-30" 
$baseURI = "https://management.azure.com"
$uri = $baseURI + ((Get-AzureRmResourceGroup -Name $rgname).ResourceId) + "/providers/Microsoft.Compute/virtualMachines/" + $vmname + "/generalize" + $suffixURI
# URI Example: 
# POST /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/generalize?api-version=2016-03-30

$params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Post'      
    URI = $uri
}
# Start the timer 
$timer.Start()

# Execute the HTTP REST call #
try { $response2 = Invoke-WebRequest @params }
catch { 
        Write-Host ("Error in the HTTP request...") -ForegroundColor Red
        Break;
       }
write-host "Step (1) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 

Write-Host ("status Code = " + $response2.StatusCode + ", Description = " + $response2.StatusDescription) # returned 202 - "ACCEPTED"

# Now let's check for the completion of the above operation: #
switch ($response2.StatusCode) 
    { 
        200 {$output = "Status returned -> 200, then SYNC operation....." } 
        201 {$output = "Status returned -> 201, then ASYNC operation....."} 
        202 {$output = "Status returned -> 202, then ASYNC operation....."} 
        default {$output = "Status returned -> " + $response2.StatusCode + "..."}
    }
Write-Host $output -ForegroundColor Green

# If long-running operation, retrieve the URL to check for completion #
if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    Write-Host ("WARNING: Response with [Azure-AsyncOperation] returned instead of [Location]") -ForegroundColor Yellow
 }
 # Response with [Azure-AsyncOperation] returned instead of [Location]
}

 $params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Get'
    URI = $URIAsyncCheck
 }
 $response3 = Invoke-WebRequest @params 
 $response3.StatusCode
 $response3.StatusDescription
 $response3.Content
 $response3.Content.Contains("InProgress")
 
 if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    While ($response3.Content.Contains("InProgress")) 
     {
       Start-Sleep -s 5;
       $response3 = Invoke-WebRequest @params
       Write-Host ("Checking  [Azure-AsyncOperation]...$($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds") -ForegroundColor Yellow
     }
    Write-Host ("Checking  [Azure-AsyncOperation]...Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green
 }
 
write-host "Step (1+2) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
write-host $response3.Content

# Stay in the loop until StatusCode will not be 200, sleep 1 second in each loop #
While ($response3.StatusCode -ne 200) 
 {
   Start-Sleep -s 1;
   $response3 = Invoke-WebRequest @params 
   Write-Host ("Waiting for completion...$($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds") -ForegroundColor Yellow
 }
 Write-Host ("Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green

} else { Write-Host "SYNC Operation, then no long running status check for completion...." -ForegroundColor Green }

$timer.Stop()
write-host "Step (1+2+3) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 

#endregion
#region SAMPLE[18]: Create a Linux IMAGE from a generalized VM #
#
# https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines#VirtualMachines_Capture 
#

[System.Reflection.Assembly]::LoadWithPartialName(“System.Diagnostics”) 
$timer = new-object system.diagnostics.stopwatch
$imagename = 'My Azure Image Name'
$rgname = 'Your Azure Resource Group Name' 
$vmname = 'Your Azure VM Name'
$location = 'Your Azure Region'
$sourceVirtualMachineID = (Get-AzureRmVM -ResourceGroupName $rgname -Name $vmname).Id
# Build URI string #
$suffixURI =  "?api-version=2016-04-30-preview" 
$baseURI = "https://management.azure.com"
$uri = $baseURI + ((Get-AzureRmResourceGroup -Name $rgname).ResourceId) + "/providers/Microsoft.Compute/images/" + $imagename + $suffixURI
# URI Example: 
# https://<endpoint>/subscriptions/{subscriptionId}/resourceGroups/{resourceG/providers/Microsoft.Compute/Images/{imageName}?api-version={api-version}

$BodyString = "{
  'location': '"+ $location + "',
  'properties': {
       'sourceVirtualMachine': {
          'id': '" + $sourceVirtualMachineID + "'
        }
  }
}"

$params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Body = $BodyString
    Method = 'Put'      
    URI = $uri
}
# Start the timer 
$timer.Start()

# Execute the HTTP REST call #
try { $response2 = Invoke-WebRequest @params }
catch { 
        Write-Host ("Error in the HTTP request...") -ForegroundColor Red
        Break;
       }
write-host "Step (1) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 

Write-Host ("status Code = " + $response2.StatusCode + ", Description = " + $response2.StatusDescription) # returned 201 - "CREATED"

# Now let's check for the completion of the above operation: #
switch ($response2.StatusCode) 
    { 
        200 {$output = "Status returned -> 200, then SYNC operation....." } 
        201 {$output = "Status returned -> 201, then ASYNC operation....."} 
        202 {$output = "Status returned -> 202, then ASYNC operation....."} 
        default {$output = "Status returned -> " + $response2.StatusCode + "..."}
    }
Write-Host $output -ForegroundColor Green

# If long-running operation, retrieve the URL to check for completion #
if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    Write-Host ("WARNING: Response with [Azure-AsyncOperation] returned instead of [Location]") -ForegroundColor Yellow
 }
 # Response with [Azure-AsyncOperation] returned instead of [Location]
}

 $params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Get'
    URI = $URIAsyncCheck
 }
 $response3 = Invoke-WebRequest @params 
 $response3.StatusCode
 $response3.StatusDescription
  
 if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    While ($response3.Content.Contains("InProgress")) 
     {
       Start-Sleep -s 5;
       $response3 = Invoke-WebRequest @params
       Write-Host ("Checking  [Azure-AsyncOperation]...$($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds") -ForegroundColor Yellow
     }
    Write-Host ("Checking  [Azure-AsyncOperation]...Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green
 }
 
write-host "Step (1+2) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
write-host $response3.Content

While (($response3.StatusCode -ne 200) -or ($response3.Content.Contains("InProgress")))
 {
   Start-Sleep -s 1;
   $response3 = Invoke-WebRequest @params 
   Write-Host ("...Response Code = " + $response3.StatusCode + " ...Content Length " + $response3.RawContentLength)
   $response3.Content
 }
 Write-Host ("Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green
 # Search for the "Status" attribute in the text blob: #
  if (($response3.Content.Contains('Succeeded')))
    { Write-Host '["Status":"Succeeded"] found in the Response Content payload....' -ForegroundColor Green }
  if (($response3.Content.Contains('Failed')))
    { Write-Host '["Status":"Failed"] found in the Response Content payload....' -ForegroundColor Red }
} else { Write-Host "SYNC Operation, then no long running status check for completion...." -ForegroundColor Green }

$timer.Stop()
write-host "Step (1+2+3) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 

#endregion 
#region SAMPLE[19]: List all created IMAGEs #
#
# PowerShell cmdlet version: 
# 
# Get-AzureRmImage -ResourceGroupName $rgname -Debug 
#
[System.Reflection.Assembly]::LoadWithPartialName(“System.Diagnostics”) 
$timer = new-object system.diagnostics.stopwatch
$vhdPrefix = 'My Azure VM prefix for VHD'
$destinationContainerName = 'myimages'
# Build URI string #
$suffixURI =  "?api-version=2016-04-30-preview"
$baseURI = "https://management.azure.com"
$uri = $baseURI + ((Get-AzureRmResourceGroup -Name $rgname).ResourceId) + "/providers/Microsoft.Compute/images" + $suffixURI
# URI Examples: 
# https://management.azure.com/subscriptions/e243327e-b18c-4766-8f44-d9    /providers/Microsoft.Compute/images?api-version=2016-04-30-preview";
# https://management.azure.com/subscriptions/8e95e0bb-d7cc-4454-9443-75ca862d34c1/resourceGroups/<Resource Group>/providers/Microsoft.Compute/images?api-version=2016-04-30-preview
# https://<endpoint>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/images/{imageName}?api-version={api-version}

$params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Get'      
    URI = $uri
}
# NOTE: $BodyString = '' is not correct, in this situations, but not be included at all in the HTTP request body.
# Start the timer 
$timer.Start()

# Execute the HTTP REST call #
try { $response2 = Invoke-WebRequest @params }
catch { 
        Write-Host ("Error in the HTTP request...") -ForegroundColor Red
        Break;
       }
write-host "Step (1) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 

Write-Host ("Status Code -> " + $response2.StatusCode + "...") -ForegroundColor Green # returned 200
Write-Host ("Status Description -> " + $response2.StatusDescription + "...") -ForegroundColor Green # returned "OK"
$response2.Content # NOTE: In case you need to show return values of GET, you need to include this line code.

# Now let's check for the completion of the above operation: #
switch ($response2.StatusCode) 
    { 
        200 {$output = "Status returned -> 200, then SYNC operation....." } 
        201 {$output = "Status returned -> 201, then ASYNC operation....."} 
        202 {$output = "Status returned -> 202, then ASYNC operation....."} 
        default {$output = "Status returned -> " + $response2.StatusCode + "..."}
    }
Write-Host $output -ForegroundColor Green

# If long-running operation, retrieve the URL to check for completion #
if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"])) 
   {
        $URIAsyncCheck = $response2.Headers["Location"]
        Write-Host ("Response with [Azure-AsyncOperation] returned...") -ForegroundColor Yellow
   } else 
        { Write-Host ("Response with [Location] returned...") -ForegroundColor Yellow }
         
 # Response with [Azure-AsyncOperation] returned instead of [Location]
}

 $params = @{
    ContentType = 'application/json'
    Headers = @{
    'authorization'="Bearer $($Token.access_token)"
    }
    Method = 'Get'
    URI = $URIAsyncCheck
 }
 
 if ($URIAsyncCheck) 
   {
    $response3 = Invoke-WebRequest @params 
    $response3.StatusCode
    $response3.StatusDescription
   }

 if ($response2.StatusCode -ne 200) 
{ 
 if (!($URIAsyncCheck = $response2.Headers["Location"])) {
    $URIAsyncCheck = $response2.Headers["Azure-AsyncOperation"]
    While ($response3.Content.Contains("InProgress")) 
     {
       Start-Sleep -s 5;
       $response3 = Invoke-WebRequest @params
       Write-Host ("Checking  [Azure-AsyncOperation]...$($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds") -ForegroundColor Yellow
     }
    Write-Host ("Checking  [Azure-AsyncOperation]...Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green
 }
 
write-host "Step (1+2) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 
write-host $response3.Content

# Stay in the loop until StatusCode will not be 200, sleep 1 second in each loop #
Write-Host ("Exited Loop -> " +  $response3.StatusCode + "....") -ForegroundColor Green
 # Search for the "Status" attribute in the text blob: #
  if (($response3.Content.Contains('Succeeded')))
    { Write-Host '["Status":"Succeeded"] found in the Response Content payload....' -ForegroundColor Green }
  if (($response3.Content.Contains('Failed')))
    { Write-Host '["Status":"Failed"] found in the Response Content payload....' -ForegroundColor Red }
} else { Write-Host "SYNC Operation, then no long running status check for completion...." -ForegroundColor Green }

$timer.Stop()
write-host "Step (1+2+3) completed in $($timer.Elapsed.Minutes) minutes, $($timer.Elapsed.Seconds) seconds" -ForegroundColor Green 

# Return the list of images: #
$response2.Content

#endregion