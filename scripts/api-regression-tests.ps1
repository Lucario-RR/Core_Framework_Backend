<#
.SYNOPSIS
Runs black-box API regression checks against a live Core Framework Backend.

.DESCRIPTION
This script creates unique fixture users and resources, then verifies happy paths,
validation errors, auth failures, admin-only access, cross-user ownership denial,
idempotency, signed file URLs, session revocation, account restrictions, and
sentinel-based data isolation. The sentinel checks are designed to catch common
SQL mistakes such as missing owner filters, incorrect joins, missing soft-delete
filters, and list endpoints that return empty or wrong data.

.EXAMPLES
Start the backend first, then run with an existing admin:

  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\api-regression-tests.ps1 `
    -AdminEmail admin@example.com `
    -AdminPassword "replace-with-admin-password"

Run against a fresh database where bootstrap admin registration is enabled:

  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\api-regression-tests.ps1 -BootstrapAdmin

Optional environment variables:

  API_TEST_ADMIN_EMAIL
  API_TEST_ADMIN_PASSWORD
#>

param(
    [string]$BaseUrl = "http://127.0.0.1:11451",
    [string]$AdminEmail = $env:API_TEST_ADMIN_EMAIL,
    [string]$AdminPassword = $env:API_TEST_ADMIN_PASSWORD,
    [switch]$BootstrapAdmin,
    [switch]$SkipPublicRegistration,
    [switch]$SkipFileTransfer,
    [switch]$StopOnFirstFailure
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:BaseUrl = $BaseUrl.TrimEnd("/")
$script:ApiRoot = "$script:BaseUrl/api/v1"
$script:RunId = "$(Get-Date -Format 'yyyyMMddHHmmss')-$(Get-Random -Minimum 1000 -Maximum 9999)"
$script:Failures = New-Object System.Collections.Generic.List[string]
$script:PassedCases = 0
$script:AcceptedLegalDocuments = @()

function Write-Info {
    param([string]$Message)
    Write-Host "[info] $Message" -ForegroundColor Cyan
}

function Write-Pass {
    param([string]$Message)
    Write-Host "  ok  $Message" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Message)
    Write-Host "  fail $Message" -ForegroundColor Red
}

function ConvertTo-RequestJson {
    param([object]$Body)
    return ($Body | ConvertTo-Json -Depth 30 -Compress)
}

function ConvertFrom-ResponseJson {
    param([string]$Content)
    if ([string]::IsNullOrWhiteSpace($Content)) {
        return $null
    }

    $trimmed = $Content.Trim()
    if (-not ($trimmed.StartsWith("{") -or $trimmed.StartsWith("["))) {
        return $null
    }

    return ($trimmed | ConvertFrom-Json)
}

function Resolve-ApiUri {
    param([string]$Path)
    if ($Path -match '^https?://') {
        return $Path
    }
    if ($Path.StartsWith("/")) {
        return "$script:ApiRoot$Path"
    }
    return "$script:ApiRoot/$Path"
}

function Get-WebRequestSkipHttpErrorSupport {
    return (Get-Command Invoke-WebRequest).Parameters.ContainsKey("SkipHttpErrorCheck")
}

function Read-ErrorResponse {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    $response = $ErrorRecord.Exception.Response
    if ($null -eq $response) {
        throw $ErrorRecord
    }

    $status = [int]$response.StatusCode
    $content = ""

    if ($response -is [System.Net.Http.HttpResponseMessage]) {
        $content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    } else {
        $stream = $response.GetResponseStream()
        if ($null -ne $stream) {
            $reader = New-Object System.IO.StreamReader($stream)
            try {
                $content = $reader.ReadToEnd()
            } finally {
                $reader.Dispose()
            }
        }
    }

    return [pscustomobject]@{
        Status  = $status
        Content = $content
        Headers = @{}
    }
}

function Invoke-Api {
    param(
        [ValidateSet("GET", "POST", "PUT", "PATCH", "DELETE")]
        [string]$Method,
        [string]$Path,
        [object]$Body = $null,
        [hashtable]$Headers = @{},
        [object]$Session = $null,
        [int[]]$ExpectedStatus = @()
    )

    $uri = Resolve-ApiUri -Path $Path
    $request = @{
        Uri         = $uri
        Method      = $Method
        Headers     = $Headers
        ErrorAction = "Stop"
    }

    if ($null -ne $Session) {
        $request.WebSession = $Session
    }

    if ($null -ne $Body) {
        $request.Body = ConvertTo-RequestJson -Body $Body
        $request.ContentType = "application/json"
    }

    if (Get-WebRequestSkipHttpErrorSupport) {
        $request.SkipHttpErrorCheck = $true
    }

    try {
        $response = Invoke-WebRequest @request
        $status = [int]$response.StatusCode
        $content = [string]$response.Content
        $headersOut = $response.Headers
    } catch {
        $errorResponse = Read-ErrorResponse -ErrorRecord $_
        $status = $errorResponse.Status
        $content = $errorResponse.Content
        $headersOut = $errorResponse.Headers
    }

    $json = ConvertFrom-ResponseJson -Content $content
    if ($ExpectedStatus.Count -gt 0 -and ($ExpectedStatus -notcontains $status)) {
        throw "Expected HTTP $($ExpectedStatus -join ',') for $Method $uri, got $status. Body: $content"
    }

    return [pscustomobject]@{
        Status  = $status
        Json    = $json
        Content = $content
        Headers = $headersOut
        Uri     = $uri
    }
}

function Invoke-RawHttp {
    param(
        [ValidateSet("GET", "PUT")]
        [string]$Method,
        [string]$Uri,
        [byte[]]$Bytes = $null,
        [string]$ContentType = $null,
        [int[]]$ExpectedStatus = @()
    )

    $request = @{
        Uri         = $Uri
        Method      = $Method
        ErrorAction = "Stop"
    }

    if ($null -ne $Bytes) {
        $request.Body = $Bytes
    }
    if (-not [string]::IsNullOrWhiteSpace($ContentType)) {
        $request.ContentType = $ContentType
    }
    if (Get-WebRequestSkipHttpErrorSupport) {
        $request.SkipHttpErrorCheck = $true
    }

    try {
        $response = Invoke-WebRequest @request
        $status = [int]$response.StatusCode
        $content = [string]$response.Content
        $headersOut = $response.Headers
    } catch {
        $errorResponse = Read-ErrorResponse -ErrorRecord $_
        $status = $errorResponse.Status
        $content = $errorResponse.Content
        $headersOut = $errorResponse.Headers
    }

    $json = ConvertFrom-ResponseJson -Content $content
    if ($ExpectedStatus.Count -gt 0 -and ($ExpectedStatus -notcontains $status)) {
        throw "Expected HTTP $($ExpectedStatus -join ',') for $Method $Uri, got $status. Body: $content"
    }

    return [pscustomobject]@{
        Status  = $status
        Json    = $json
        Content = $content
        Headers = $headersOut
        Uri     = $Uri
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw "Assertion failed: $Message"
    }
    Write-Pass $Message
}

function Assert-Equal {
    param([object]$Expected, [object]$Actual, [string]$Message)
    if ($Expected -ne $Actual) {
        throw "Assertion failed: $Message. Expected '$Expected', got '$Actual'."
    }
    Write-Pass $Message
}

function Assert-NotNull {
    param([object]$Value, [string]$Message)
    if ($null -eq $Value) {
        throw "Assertion failed: $Message"
    }
    Write-Pass $Message
}

function Assert-NotBlank {
    param([string]$Value, [string]$Message)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "Assertion failed: $Message"
    }
    Write-Pass $Message
}

function Assert-ApiError {
    param([object]$Response, [string]$Code)
    Assert-NotNull $Response.Json "error response is JSON"
    Assert-NotNull $Response.Json.error "error envelope exists"
    Assert-Equal $Code $Response.Json.error.code "error code is $Code"
    Assert-True (($Response.Json.error.urgencyLevel -ge 1) -and ($Response.Json.error.urgencyLevel -le 9)) "error urgencyLevel is between 1 and 9"
    Assert-NotBlank ([string]$Response.Json.error.requestId) "error requestId is present"
}

function Find-ItemById {
    param([object[]]$Items, [string]$Id)
    return (@($Items) | Where-Object { [string]$_.id -eq [string]$Id } | Select-Object -First 1)
}

function Assert-CollectionContainsId {
    param([object[]]$Items, [string]$Id, [string]$Message)
    $match = Find-ItemById -Items $Items -Id $Id
    Assert-NotNull $match $Message
    return $match
}

function Assert-CollectionDoesNotContainId {
    param([object[]]$Items, [string]$Id, [string]$Message)
    $match = Find-ItemById -Items $Items -Id $Id
    Assert-True ($null -eq $match) $Message
}

function New-TestPassword {
    return "CodexSafePwd!42"
}

function New-TestUsername {
    param([string]$Prefix)
    $safeRunId = ($script:RunId -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
    return "$Prefix$safeRunId"
}

function New-Actor {
    param([string]$Name, [string]$Email, [string]$Password)
    return [pscustomobject]@{
        Name        = $Name
        Email       = $Email
        Password    = $Password
        Session     = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        AccessToken = $null
        AccountId   = $null
    }
}

function Set-ActorFromAuthResponse {
    param([object]$Actor, [object]$Response)
    Assert-NotNull $Response.Json.data.accessToken "$($Actor.Name) auth response has accessToken"
    Assert-NotNull $Response.Json.data.user.id "$($Actor.Name) auth response has user id"
    $Actor.AccessToken = [string]$Response.Json.data.accessToken
    $Actor.AccountId = [string]$Response.Json.data.user.id
}

function Get-AuthHeaders {
    param([object]$Actor)
    return @{ Authorization = "Bearer $($Actor.AccessToken)" }
}

function Invoke-Login {
    param([object]$Actor)
    $response = Invoke-Api `
        -Method POST `
        -Path "/auth/login" `
        -Session $Actor.Session `
        -Body @{
            login      = $Actor.Email
            password   = $Actor.Password
            rememberMe = $true
        } `
        -ExpectedStatus @(200, 202)

    if ($response.Status -eq 202) {
        throw "$($Actor.Name) login returned an MFA challenge. Use a test account without active TOTP, or bootstrap a fresh admin account."
    }

    Set-ActorFromAuthResponse -Actor $Actor -Response $response
    return $response
}

function Get-CookieValue {
    param([object]$Session, [string]$Name)
    $cookies = $Session.Cookies.GetCookies([Uri]$script:BaseUrl)
    foreach ($cookie in $cookies) {
        if ($cookie.Name -eq $Name) {
            return $cookie.Value
        }
    }
    return $null
}

function Get-HeaderValue {
    param([object]$Headers, [string]$Name)
    if ($null -eq $Headers) {
        return $null
    }

    try {
        $direct = $Headers[$Name]
        if ($null -ne $direct) {
            if ($direct -is [array]) {
                return [string]$direct[0]
            }
            return [string]$direct
        }
    } catch {
        # Different PowerShell versions expose Invoke-WebRequest headers differently.
    }

    if ($Headers -is [System.Collections.IDictionary]) {
        foreach ($key in $Headers.Keys) {
            if ([string]::Equals([string]$key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                $value = $Headers[$key]
                if ($value -is [array]) {
                    return [string]$value[0]
                }
                return [string]$value
            }
        }
    }

    if ($Headers.PSObject.Properties.Name -contains "AllKeys") {
        foreach ($key in $Headers.AllKeys) {
            if ([string]::Equals([string]$key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return [string]$Headers[$key]
            }
        }
    }

    return $null
}

function New-LegalAcceptances {
    return @($script:AcceptedLegalDocuments | ForEach-Object {
        @{
            documentKey = $_.documentKey
            version     = $_.version
        }
    })
}

function New-AdminUserFixture {
    param(
        [object]$Admin,
        [string]$Name,
        [string]$Email,
        [string]$Password,
        [string]$DisplayName
    )

    $response = Invoke-Api `
        -Method POST `
        -Path "/admin/users" `
        -Headers (Get-AuthHeaders -Actor $Admin) `
        -Session $Admin.Session `
        -Body @{
            username      = New-TestUsername -Prefix ($Name.ToLowerInvariant())
            email         = $Email
            password      = $Password
            displayName   = $DisplayName
            primaryPhone  = $null
            roleCodes     = @("user")
            accountStatus = "active"
        } `
        -ExpectedStatus 201

    Assert-Equal $Email $response.Json.data.user.primaryEmail "$Name primary email matches fixture"
    Assert-Equal $DisplayName $response.Json.data.user.displayName "$Name displayName matches fixture"

    $actor = New-Actor -Name $Name -Email $Email -Password $Password
    $actor.AccountId = [string]$response.Json.data.user.id
    return $actor
}

function Run-Case {
    param([string]$Name, [scriptblock]$Body)
    Write-Host ""
    Write-Host "== $Name ==" -ForegroundColor Yellow
    try {
        & $Body
        $script:PassedCases += 1
        Write-Host "PASS $Name" -ForegroundColor Green
    } catch {
        $message = "$Name :: $($_.Exception.Message)"
        $script:Failures.Add($message)
        Write-Fail $message
        if ($StopOnFirstFailure) {
            throw
        }
    }
}

Write-Info "API root: $script:ApiRoot"
Write-Info "Run id: $script:RunId"
Write-Info "Use -AdminEmail/-AdminPassword or API_TEST_ADMIN_EMAIL/API_TEST_ADMIN_PASSWORD for an existing admin."
Write-Info "Use -BootstrapAdmin only on a fresh database with PUBLIC_ADMIN_BOOTSTRAP_ENABLED=true."

$password = New-TestPassword
$publicUser = New-Actor -Name "publicUser" -Email "api-public-$script:RunId@example.test" -Password $password
$admin = New-Actor -Name "admin" -Email $(if ($AdminEmail) { $AdminEmail } else { "api-admin-$script:RunId@example.test" }) -Password $(if ($AdminPassword) { $AdminPassword } else { $password })
$userA = $null
$userB = $null
$userASecondSession = $null
$userAPrivacyRequestId = $null
$userBPrivacyRequestId = $null
$userAFileId = $null

Run-Case "Public health, policy, and legal documents" {
    $health = Invoke-Api -Method GET -Path "/health" -ExpectedStatus 200
    Assert-Equal "ok" $health.Json.data.status "health endpoint returns ok"

    $policy = Invoke-Api -Method GET -Path "/auth/password/policy" -ExpectedStatus 200
    Assert-True ($policy.Json.data.minLength -ge 1) "password policy has a valid minLength"

    $legal = Invoke-Api -Method GET -Path "/legal/documents" -ExpectedStatus 200
    $script:AcceptedLegalDocuments = @($legal.Json.data)
    Assert-True ($script:AcceptedLegalDocuments.Count -gt 0) "legal documents are available for registration"
    foreach ($document in $script:AcceptedLegalDocuments) {
        Assert-NotBlank ([string]$document.documentKey) "legal document has documentKey"
        Assert-NotBlank ([string]$document.version) "legal document has version"
    }
}

Run-Case "Public registration validation and happy path" {
    if ($SkipPublicRegistration) {
        Write-Info "Skipping public registration checks because -SkipPublicRegistration was set."
        return
    }

    $missingDocs = Invoke-Api `
        -Method POST `
        -Path "/auth/register" `
        -Session $publicUser.Session `
        -Body @{
            username               = New-TestUsername -Prefix "missingdocs"
            email                  = "api-missing-docs-$script:RunId@example.test"
            password               = $password
            displayName            = "Missing Docs $script:RunId"
            primaryPhone           = $null
            invitationCode         = $null
            acceptedLegalDocuments = @()
        } `
        -ExpectedStatus 400
    Assert-ApiError -Response $missingDocs -Code "VALIDATION_ERROR"

    $registered = Invoke-Api `
        -Method POST `
        -Path "/auth/register" `
        -Session $publicUser.Session `
        -Body @{
            username               = New-TestUsername -Prefix "public"
            email                  = $publicUser.Email
            password               = $publicUser.Password
            displayName            = "Public API Test $script:RunId"
            primaryPhone           = $null
            invitationCode         = $null
            acceptedLegalDocuments = New-LegalAcceptances
        } `
        -ExpectedStatus 201

    Set-ActorFromAuthResponse -Actor $publicUser -Response $registered
    $me = Invoke-Api -Method GET -Path "/me" -Headers (Get-AuthHeaders -Actor $publicUser) -Session $publicUser.Session -ExpectedStatus 200
    Assert-Equal $publicUser.AccountId ([string]$me.Json.data.id) "registered user can read own profile"
}

Run-Case "Admin authentication" {
    if ($AdminEmail -and $AdminPassword) {
        $null = Invoke-Login -Actor $admin
    } elseif ($BootstrapAdmin) {
        $bootstrap = Invoke-Api `
            -Method POST `
            -Path "/auth/register-admin" `
            -Session $admin.Session `
            -Body @{
                username               = New-TestUsername -Prefix "admin"
                email                  = $admin.Email
                password               = $admin.Password
                displayName            = "Bootstrap API Test Admin $script:RunId"
                primaryPhone           = $null
                invitationCode         = $null
                acceptedLegalDocuments = New-LegalAcceptances
            } `
            -ExpectedStatus 201
        Set-ActorFromAuthResponse -Actor $admin -Response $bootstrap
    } else {
        throw "Admin credentials were not supplied. Pass -AdminEmail/-AdminPassword, set API_TEST_ADMIN_EMAIL/API_TEST_ADMIN_PASSWORD, or use -BootstrapAdmin on a fresh database."
    }

    $overview = Invoke-Api -Method GET -Path "/admin/overview" -Headers (Get-AuthHeaders -Actor $admin) -Session $admin.Session -ExpectedStatus 200
    Assert-True ($overview.Json.data.accountCount -ge 1) "admin can read platform overview"

    $noAuth = Invoke-Api -Method GET -Path "/admin/overview" -ExpectedStatus 401
    Assert-ApiError -Response $noAuth -Code "UNAUTHORIZED"
}

Run-Case "Admin user creation, duplicate detection, and non-admin denial" {
    $weakUser = Invoke-Api `
        -Method POST `
        -Path "/admin/users" `
        -Headers (Get-AuthHeaders -Actor $admin) `
        -Session $admin.Session `
        -Body @{
            username      = New-TestUsername -Prefix "weak"
            email         = "api-weak-$script:RunId@example.test"
            password      = "short1"
            displayName   = "Weak Password $script:RunId"
            primaryPhone  = $null
            roleCodes     = @("user")
            accountStatus = "active"
        } `
        -ExpectedStatus 400
    Assert-ApiError -Response $weakUser -Code "VALIDATION_ERROR"

    $script:userA = New-AdminUserFixture -Admin $admin -Name "userA" -Email "api-user-a-$script:RunId@example.test" -Password $password -DisplayName "API User A $script:RunId"
    $script:userB = New-AdminUserFixture -Admin $admin -Name "userB" -Email "api-user-b-$script:RunId@example.test" -Password $password -DisplayName "API User B $script:RunId"

    $duplicate = Invoke-Api `
        -Method POST `
        -Path "/admin/users" `
        -Headers (Get-AuthHeaders -Actor $admin) `
        -Session $admin.Session `
        -Body @{
            username      = New-TestUsername -Prefix "duplicate"
            email         = $script:userA.Email
            password      = $password
            displayName   = "Duplicate User $script:RunId"
            primaryPhone  = $null
            roleCodes     = @("user")
            accountStatus = "active"
        } `
        -ExpectedStatus 409
    Assert-ApiError -Response $duplicate -Code "CONFLICT"

    $null = Invoke-Login -Actor $script:userA
    $null = Invoke-Login -Actor $script:userB

    $adminAttempt = Invoke-Api -Method GET -Path "/admin/overview" -Headers (Get-AuthHeaders -Actor $script:userA) -Session $script:userA.Session -ExpectedStatus 403
    Assert-ApiError -Response $adminAttempt -Code "FORBIDDEN"

    $users = Invoke-Api `
        -Method GET `
        -Path "/admin/users?query=$([Uri]::EscapeDataString($script:RunId))&limit=50" `
        -Headers (Get-AuthHeaders -Actor $admin) `
        -Session $admin.Session `
        -ExpectedStatus 200
    $items = @($users.Json.data)
    $null = Assert-CollectionContainsId -Items $items -Id $script:userA.AccountId -Message "admin user search contains user A sentinel"
    $null = Assert-CollectionContainsId -Items $items -Id $script:userB.AccountId -Message "admin user search contains user B sentinel"
}

Run-Case "Profile reads and optimistic concurrency" {
    $unauthenticated = Invoke-Api -Method GET -Path "/me" -ExpectedStatus 401
    Assert-ApiError -Response $unauthenticated -Code "UNAUTHORIZED"

    $meA = Invoke-Api -Method GET -Path "/me" -Headers (Get-AuthHeaders -Actor $script:userA) -Session $script:userA.Session -ExpectedStatus 200
    Assert-Equal $script:userA.AccountId ([string]$meA.Json.data.id) "user A /me returns user A id"
    Assert-Equal $script:userA.Email ([string]$meA.Json.data.primaryEmail) "user A /me returns user A email"

    $meB = Invoke-Api -Method GET -Path "/me" -Headers (Get-AuthHeaders -Actor $script:userB) -Session $script:userB.Session -ExpectedStatus 200
    Assert-Equal $script:userB.AccountId ([string]$meB.Json.data.id) "user B /me returns user B id"
    Assert-Equal $script:userB.Email ([string]$meB.Json.data.primaryEmail) "user B /me returns user B email"

    $etag = Get-HeaderValue -Headers $meA.Headers -Name "ETag"
    Assert-NotBlank $etag "GET /me returns an ETag"

    $updated = Invoke-Api `
        -Method PATCH `
        -Path "/me" `
        -Headers @{
            Authorization = "Bearer $($script:userA.AccessToken)"
            "If-Match"   = $etag
        } `
        -Session $script:userA.Session `
        -Body @{
            displayName     = "API User A Updated $script:RunId"
            defaultCurrency = $null
            locale          = $null
            timezoneName    = $null
            profileBio      = "profile sentinel $script:RunId"
        } `
        -ExpectedStatus 200
    Assert-Equal "API User A Updated $script:RunId" ([string]$updated.Json.data.displayName) "profile update writes expected displayName"

    $stale = Invoke-Api `
        -Method PATCH `
        -Path "/me" `
        -Headers @{
            Authorization = "Bearer $($script:userA.AccessToken)"
            "If-Match"   = $etag
        } `
        -Session $script:userA.Session `
        -Body @{
            displayName     = "Should Not Persist $script:RunId"
            defaultCurrency = $null
            locale          = $null
            timezoneName    = $null
            profileBio      = $null
        } `
        -ExpectedStatus 412
    Assert-ApiError -Response $stale -Code "PRECONDITION_FAILED"
}

Run-Case "Email and phone ownership checks" {
    $emailA = Invoke-Api `
        -Method POST `
        -Path "/me/emails" `
        -Headers (Get-AuthHeaders -Actor $script:userA) `
        -Session $script:userA.Session `
        -Body @{
            email = "api-user-a-alt-$script:RunId@example.test"
            label = "security"
        } `
        -ExpectedStatus 201
    $emailAId = [string]$emailA.Json.data.id
    Assert-NotBlank $emailAId "user A secondary email id returned"

    $emailsA = Invoke-Api -Method GET -Path "/me/emails" -Headers (Get-AuthHeaders -Actor $script:userA) -Session $script:userA.Session -ExpectedStatus 200
    $null = Assert-CollectionContainsId -Items @($emailsA.Json.data) -Id $emailAId -Message "user A email list contains new email"

    $crossDeleteEmail = Invoke-Api -Method DELETE -Path "/me/emails/$emailAId" -Headers (Get-AuthHeaders -Actor $script:userB) -Session $script:userB.Session -ExpectedStatus 404
    Assert-ApiError -Response $crossDeleteEmail -Code "NOT_FOUND"

    $unverifiedPrimary = Invoke-Api -Method POST -Path "/me/emails/$emailAId/make-primary" -Headers (Get-AuthHeaders -Actor $script:userA) -Session $script:userA.Session -ExpectedStatus 409
    Assert-ApiError -Response $unverifiedPrimary -Code "CONFLICT"

    $phoneAValue = "+4477009$(Get-Random -Minimum 100000 -Maximum 999999)"
    $phoneA = Invoke-Api `
        -Method POST `
        -Path "/me/phones" `
        -Headers (Get-AuthHeaders -Actor $script:userA) `
        -Session $script:userA.Session `
        -Body @{
            phoneNumber = $phoneAValue
            label       = "backup"
        } `
        -ExpectedStatus 201
    $phoneAId = [string]$phoneA.Json.data.id
    Assert-NotBlank $phoneAId "user A phone id returned"

    $phonesA = Invoke-Api -Method GET -Path "/me/phones" -Headers (Get-AuthHeaders -Actor $script:userA) -Session $script:userA.Session -ExpectedStatus 200
    $null = Assert-CollectionContainsId -Items @($phonesA.Json.data) -Id $phoneAId -Message "user A phone list contains new phone"

    $crossDeletePhone = Invoke-Api -Method DELETE -Path "/me/phones/$phoneAId" -Headers (Get-AuthHeaders -Actor $script:userB) -Session $script:userB.Session -ExpectedStatus 404
    Assert-ApiError -Response $crossDeletePhone -Code "NOT_FOUND"

    $unverifiedPhonePrimary = Invoke-Api -Method POST -Path "/me/phones/$phoneAId/make-primary" -Headers (Get-AuthHeaders -Actor $script:userA) -Session $script:userA.Session -ExpectedStatus 409
    Assert-ApiError -Response $unverifiedPhonePrimary -Code "CONFLICT"
}

Run-Case "Privacy request data isolation" {
    $requestA = Invoke-Api `
        -Method POST `
        -Path "/me/privacy-requests" `
        -Headers (Get-AuthHeaders -Actor $script:userA) `
        -Session $script:userA.Session `
        -Body @{
            requestType = "ACCESS_EXPORT"
            notes       = "privacy sentinel A $script:RunId"
        } `
        -ExpectedStatus 201
    $script:userAPrivacyRequestId = [string]$requestA.Json.data.id

    $requestB = Invoke-Api `
        -Method POST `
        -Path "/me/privacy-requests" `
        -Headers (Get-AuthHeaders -Actor $script:userB) `
        -Session $script:userB.Session `
        -Body @{
            requestType = "ERASURE"
            notes       = "privacy sentinel B $script:RunId"
        } `
        -ExpectedStatus 201
    $script:userBPrivacyRequestId = [string]$requestB.Json.data.id

    $listA = Invoke-Api -Method GET -Path "/me/privacy-requests?limit=20" -Headers (Get-AuthHeaders -Actor $script:userA) -Session $script:userA.Session -ExpectedStatus 200
    $itemsA = @($listA.Json.data)
    $null = Assert-CollectionContainsId -Items $itemsA -Id $script:userAPrivacyRequestId -Message "user A privacy list contains user A request"
    Assert-CollectionDoesNotContainId -Items $itemsA -Id $script:userBPrivacyRequestId -Message "user A privacy list excludes user B request"

    $crossRead = Invoke-Api -Method GET -Path "/me/privacy-requests/$script:userAPrivacyRequestId" -Headers (Get-AuthHeaders -Actor $script:userB) -Session $script:userB.Session -ExpectedStatus 404
    Assert-ApiError -Response $crossRead -Code "NOT_FOUND"

    $anonSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $setPrefs = Invoke-Api `
        -Method PUT `
        -Path "/privacy/cookie-preferences" `
        -Session $anonSession `
        -Body @{
            preferences = $true
            analytics   = $false
            marketing   = $true
        } `
        -ExpectedStatus 200
    Assert-Equal $true $setPrefs.Json.data.preferences "anonymous cookie preferences persist preferences flag"
    Assert-Equal $true $setPrefs.Json.data.marketing "anonymous cookie preferences persist marketing flag"

    $getPrefs = Invoke-Api -Method GET -Path "/privacy/cookie-preferences" -Session $anonSession -ExpectedStatus 200
    Assert-Equal $true $getPrefs.Json.data.preferences "anonymous cookie preferences can be read back"
    Assert-Equal $false $getPrefs.Json.data.analytics "anonymous cookie preferences preserve analytics flag"
}

Run-Case "File upload, idempotency, signed URL, and ownership checks" {
    if ($SkipFileTransfer) {
        Write-Info "Skipping file transfer checks because -SkipFileTransfer was set."
        return
    }

    $uploadText = "API upload sentinel $script:RunId"
    $uploadBytes = [System.Text.Encoding]::UTF8.GetBytes($uploadText)

    $missingIdempotency = Invoke-Api `
        -Method POST `
        -Path "/files/uploads" `
        -Headers (Get-AuthHeaders -Actor $script:userA) `
        -Session $script:userA.Session `
        -Body @{
            filename       = "missing-idempotency-$script:RunId.txt"
            contentType    = "text/plain"
            size           = $uploadBytes.Length
            purpose        = "user_avatar"
            checksumSha256 = $null
        } `
        -ExpectedStatus 400
    Assert-ApiError -Response $missingIdempotency -Code "VALIDATION_ERROR"

    $idempotencyKey = "api-file-$script:RunId"
    $intent = Invoke-Api `
        -Method POST `
        -Path "/files/uploads" `
        -Headers @{
            Authorization     = "Bearer $($script:userA.AccessToken)"
            "Idempotency-Key" = $idempotencyKey
        } `
        -Session $script:userA.Session `
        -Body @{
            filename       = "avatar-$script:RunId.txt"
            contentType    = "text/plain"
            size           = $uploadBytes.Length
            purpose        = "user_avatar"
            checksumSha256 = $null
        } `
        -ExpectedStatus 201
    $script:userAFileId = [string]$intent.Json.data.fileId
    Assert-NotBlank $script:userAFileId "file intent returns fileId"
    Assert-NotBlank ([string]$intent.Json.data.uploadUrl) "file intent returns signed upload URL"

    $repeatIntent = Invoke-Api `
        -Method POST `
        -Path "/files/uploads" `
        -Headers @{
            Authorization     = "Bearer $($script:userA.AccessToken)"
            "Idempotency-Key" = $idempotencyKey
        } `
        -Session $script:userA.Session `
        -Body @{
            filename       = "avatar-$script:RunId.txt"
            contentType    = "text/plain"
            size           = $uploadBytes.Length
            purpose        = "user_avatar"
            checksumSha256 = $null
        } `
        -ExpectedStatus 201
    Assert-Equal $script:userAFileId ([string]$repeatIntent.Json.data.fileId) "reused Idempotency-Key returns the same file id"

    $crossReadFile = Invoke-Api -Method GET -Path "/me/files/$script:userAFileId" -Headers (Get-AuthHeaders -Actor $script:userB) -Session $script:userB.Session -ExpectedStatus 404
    Assert-ApiError -Response $crossReadFile -Code "NOT_FOUND"

    $tamperedUploadUrl = [regex]::Replace([string]$intent.Json.data.uploadUrl, 'signature=[^&]+', 'signature=bad')
    $tamperedUpload = Invoke-RawHttp -Method PUT -Uri $tamperedUploadUrl -Bytes $uploadBytes -ContentType "text/plain" -ExpectedStatus 401
    Assert-ApiError -Response $tamperedUpload -Code "UNAUTHORIZED"

    $upload = Invoke-RawHttp -Method PUT -Uri ([string]$intent.Json.data.uploadUrl) -Bytes $uploadBytes -ContentType "text/plain" -ExpectedStatus 204
    Assert-Equal 204 $upload.Status "signed upload accepts expected bytes"

    $complete = Invoke-Api -Method POST -Path "/files/uploads/$script:userAFileId/complete" -Headers (Get-AuthHeaders -Actor $script:userA) -Session $script:userA.Session -ExpectedStatus 200
    Assert-Equal "ready" ([string]$complete.Json.data.status) "complete upload marks file ready"
    Assert-Equal "avatar-$script:RunId.txt" ([string]$complete.Json.data.filename) "completed file keeps expected filename"

    $avatar = Invoke-Api `
        -Method POST `
        -Path "/me/avatar" `
        -Headers (Get-AuthHeaders -Actor $script:userA) `
        -Session $script:userA.Session `
        -Body @{ fileId = $script:userAFileId } `
        -ExpectedStatus 200
    Assert-Equal $script:userAFileId ([string]$avatar.Json.data.avatarFileId) "user A can assign own ready avatar file"

    $crossAvatar = Invoke-Api `
        -Method POST `
        -Path "/me/avatar" `
        -Headers (Get-AuthHeaders -Actor $script:userB) `
        -Session $script:userB.Session `
        -Body @{ fileId = $script:userAFileId } `
        -ExpectedStatus 404
    Assert-ApiError -Response $crossAvatar -Code "NOT_FOUND"

    $downloadIntent = Invoke-Api -Method GET -Path "/me/files/$script:userAFileId/download" -Headers (Get-AuthHeaders -Actor $script:userA) -Session $script:userA.Session -ExpectedStatus 200
    Assert-NotBlank ([string]$downloadIntent.Json.data.url) "download intent returns signed URL"

    $download = Invoke-RawHttp -Method GET -Uri ([string]$downloadIntent.Json.data.url) -ExpectedStatus 200
    Assert-Equal $uploadText ([string]$download.Content) "signed download returns uploaded content"

    $tamperedDownloadUrl = [regex]::Replace([string]$downloadIntent.Json.data.url, 'signature=[^&]+', 'signature=bad')
    $tamperedDownload = Invoke-RawHttp -Method GET -Uri $tamperedDownloadUrl -ExpectedStatus 401
    Assert-ApiError -Response $tamperedDownload -Code "UNAUTHORIZED"
}

Run-Case "Refresh, session listing, and session ownership checks" {
    $missingCsrf = Invoke-Api -Method POST -Path "/auth/refresh" -Session $script:userA.Session -ExpectedStatus 401
    Assert-ApiError -Response $missingCsrf -Code "UNAUTHORIZED"

    $csrf = Get-CookieValue -Session $script:userA.Session -Name "csrf_token"
    Assert-NotBlank $csrf "login stored csrf_token cookie"

    $refresh = Invoke-Api `
        -Method POST `
        -Path "/auth/refresh" `
        -Headers @{ "X-CSRF-Token" = $csrf } `
        -Session $script:userA.Session `
        -ExpectedStatus 200
    Set-ActorFromAuthResponse -Actor $script:userA -Response $refresh

    $script:userASecondSession = New-Actor -Name "userASecondSession" -Email $script:userA.Email -Password $script:userA.Password
    $null = Invoke-Login -Actor $script:userASecondSession

    $sessions = Invoke-Api -Method GET -Path "/me/sessions?limit=20" -Headers (Get-AuthHeaders -Actor $script:userA) -Session $script:userA.Session -ExpectedStatus 200
    $sessionItems = @($sessions.Json.data)
    Assert-True ($sessionItems.Count -ge 2) "user A session list contains at least two sessions"

    $otherSession = $sessionItems | Where-Object { $_.isCurrent -eq $false } | Select-Object -First 1
    Assert-NotNull $otherSession "user A session list exposes a non-current session"
    $otherSessionId = [string]$otherSession.id

    $crossRevoke = Invoke-Api -Method DELETE -Path "/me/sessions/$otherSessionId" -Headers (Get-AuthHeaders -Actor $script:userB) -Session $script:userB.Session -ExpectedStatus 404
    Assert-ApiError -Response $crossRevoke -Code "NOT_FOUND"

    $ownRevoke = Invoke-Api -Method DELETE -Path "/me/sessions/$otherSessionId" -Headers (Get-AuthHeaders -Actor $script:userA) -Session $script:userA.Session -ExpectedStatus 204
    Assert-Equal 204 $ownRevoke.Status "user A can revoke own non-current session"

    $revokedTokenUse = Invoke-Api -Method GET -Path "/me" -Headers (Get-AuthHeaders -Actor $script:userASecondSession) -Session $script:userASecondSession.Session -ExpectedStatus 401
    Assert-ApiError -Response $revokedTokenUse -Code "UNAUTHORIZED"
}

Run-Case "Admin account restriction revokes access" {
    $suspended = Invoke-Api `
        -Method PATCH `
        -Path "/admin/users/$($script:userB.AccountId)" `
        -Headers (Get-AuthHeaders -Actor $admin) `
        -Session $admin.Session `
        -Body @{
            username                = $null
            displayName             = $null
            primaryEmail            = $null
            primaryPhone            = $null
            roleCodes               = $null
            accountStatus           = "suspended"
            requirePasswordChange   = $null
            requireMfaEnrollment    = $null
            disableLogin            = $null
            defaultCurrency         = $null
            locale                  = $null
            timezoneName            = $null
            profileBio              = $null
            reason                  = "API regression suspension $script:RunId"
        } `
        -ExpectedStatus 200
    Assert-Equal "suspended" ([string]$suspended.Json.data.status) "admin can suspend fixture user"

    $oldTokenUse = Invoke-Api -Method GET -Path "/me" -Headers (Get-AuthHeaders -Actor $script:userB) -Session $script:userB.Session -ExpectedStatus 401
    Assert-ApiError -Response $oldTokenUse -Code "UNAUTHORIZED"

    $freshSuspendedLogin = Invoke-Api `
        -Method POST `
        -Path "/auth/login" `
        -Session (New-Object Microsoft.PowerShell.Commands.WebRequestSession) `
        -Body @{
            login      = $script:userB.Email
            password   = $script:userB.Password
            rememberMe = $false
        } `
        -ExpectedStatus 403
    Assert-ApiError -Response $freshSuspendedLogin -Code "FORBIDDEN"

    $restored = Invoke-Api `
        -Method PATCH `
        -Path "/admin/users/$($script:userB.AccountId)" `
        -Headers (Get-AuthHeaders -Actor $admin) `
        -Session $admin.Session `
        -Body @{
            username                = $null
            displayName             = $null
            primaryEmail            = $null
            primaryPhone            = $null
            roleCodes               = $null
            accountStatus           = "active"
            requirePasswordChange   = $null
            requireMfaEnrollment    = $null
            disableLogin            = $null
            defaultCurrency         = $null
            locale                  = $null
            timezoneName            = $null
            profileBio              = $null
            reason                  = "API regression restore $script:RunId"
        } `
        -ExpectedStatus 200
    Assert-Equal "active" ([string]$restored.Json.data.status) "admin can restore fixture user to active"
}

Run-Case "Admin audit and security list access" {
    $securityEvents = Invoke-Api -Method GET -Path "/admin/security/events?limit=10" -Headers (Get-AuthHeaders -Actor $admin) -Session $admin.Session -ExpectedStatus 200
    Assert-NotNull $securityEvents.Json.data "admin security events list returns a data array"

    $auditLogs = Invoke-Api -Method GET -Path "/admin/audit-logs?limit=10" -Headers (Get-AuthHeaders -Actor $admin) -Session $admin.Session -ExpectedStatus 200
    Assert-NotNull $auditLogs.Json.data "admin audit logs list returns a data array"

    $nonAdminAudit = Invoke-Api -Method GET -Path "/admin/audit-logs?limit=10" -Headers (Get-AuthHeaders -Actor $script:userA) -Session $script:userA.Session -ExpectedStatus 403
    Assert-ApiError -Response $nonAdminAudit -Code "FORBIDDEN"
}

Write-Host ""
Write-Host "===================="
Write-Host "API regression result"
Write-Host "===================="
Write-Host "Run id: $script:RunId"
Write-Host "Passed cases: $script:PassedCases"
Write-Host "Failed cases: $($script:Failures.Count)"

if ($script:Failures.Count -gt 0) {
    Write-Host ""
    Write-Host "Failures:" -ForegroundColor Red
    foreach ($failure in $script:Failures) {
        Write-Host "- $failure" -ForegroundColor Red
    }
    exit 1
}

Write-Host "All API regression checks passed." -ForegroundColor Green
exit 0
