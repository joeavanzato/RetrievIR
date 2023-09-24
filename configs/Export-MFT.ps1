# Modified from https://gist.github.com/secabstraction/4044f4aadd3ef21f0ca9
$CSV = "C:\Windows\Temp\MFT.csv"
$Volume = 0
$ScriptTime = [Diagnostics.Stopwatch]::StartNew()

if ($Volume -ne 0) { 
    $Win32_Volume = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter LIKE '$($Volume):'"
    if ($Win32_Volume.FileSystem -ne "NTFS") { 
        Write-Error "$Volume is not an NTFS filesystem."
        break
    }
}
else {
    $Win32_Volume = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter LIKE '$($env:SystemDrive)'"
    if ($Win32_Volume.FileSystem -ne "NTFS") { 
        Write-Error "$env:SystemDrive is not an NTFS filesystem."
        break
    }
}

$OutputFilePath = "#FILEPATH#"

#region WinAPI

$GENERIC_READWRITE = 0x80000000
$FILE_SHARE_READWRITE = 0x02 -bor 0x01
$OPEN_EXISTING = 0x03

$DynAssembly = New-Object System.Reflection.AssemblyName('MFT')
$AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemory', $false)

$TypeBuilder = $ModuleBuilder.DefineType('kernel32', 'Public, Class')
$DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
$SetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
$SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor,
    @('kernel32.dll'),
    [Reflection.FieldInfo[]]@($SetLastError),
    @($True))

#CreateFile
$PInvokeMethodBuilder = $TypeBuilder.DefinePInvokeMethod('CreateFile', 'kernel32.dll',
    ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
    [Reflection.CallingConventions]::Standard,
    [IntPtr],
    [Type[]]@([String], [Int32], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr]),
    [Runtime.InteropServices.CallingConvention]::Winapi,
    [Runtime.InteropServices.CharSet]::Ansi)
$PInvokeMethodBuilder.SetCustomAttribute($SetLastErrorCustomAttribute)

#CloseHandle
$PInvokeMethodBuilder = $TypeBuilder.DefinePInvokeMethod('CloseHandle', 'kernel32.dll',
    ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
    [Reflection.CallingConventions]::Standard,
    [Bool],
    [Type[]]@([IntPtr]),
    [Runtime.InteropServices.CallingConvention]::Winapi,
    [Runtime.InteropServices.CharSet]::Auto)
$PInvokeMethodBuilder.SetCustomAttribute($SetLastErrorCustomAttribute)

$Kernel32 = $TypeBuilder.CreateType()

#endregion WinAPI

# Get handle to volume
if ($Volume -ne 0) { $VolumeHandle = $Kernel32::CreateFile(('\\.\' + $Volume + ':'), $GENERIC_READWRITE, $FILE_SHARE_READWRITE, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero) }
else { 
    $VolumeHandle = $Kernel32::CreateFile(('\\.\' + $env:SystemDrive), $GENERIC_READWRITE, $FILE_SHARE_READWRITE, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero) 
    $Volume = ($env:SystemDrive).TrimEnd(':')
}
        
if ($VolumeHandle -eq -1) { 
    Write-Error "Unable to obtain read handle for volume."
    break 
}         
        
# Create a FileStream to read from the volume handle
$FileStream = New-Object IO.FileStream($VolumeHandle, [IO.FileAccess]::Read)                   

# Read VBR from volume
$VolumeBootRecord = New-Object Byte[](512)                                                     
if ($FileStream.Read($VolumeBootRecord, 0, $VolumeBootRecord.Length) -ne 512) { Write-Error "Error reading volume boot record." }

# Parse MFT offset from VBR and set stream to its location
$MftOffset = [Bitconverter]::ToInt32($VolumeBootRecord[0x30..0x37], 0) * 0x1000
$FileStream.Position = $MftOffset

# Read MFT's file record header
$MftFileRecordHeader = New-Object byte[](48)
if ($FileStream.Read($MftFileRecordHeader, 0, $MftFileRecordHeader.Length) -ne $MftFileRecordHeader.Length) { Write-Error "Error reading MFT file record header." }

# Parse values from MFT's file record header
$OffsetToAttributes = [Bitconverter]::ToInt16($MftFileRecordHeader[0x14..0x15], 0)
$AttributesRealSize = [Bitconverter]::ToInt32($MftFileRecordHeader[0x18..0x21], 0)

# Read MFT's full file record
$MftFileRecord = New-Object byte[]($AttributesRealSize)
$FileStream.Position = $MftOffset
if ($FileStream.Read($MftFileRecord, 0, $MftFileRecord.Length) -ne $AttributesRealSize) { Write-Error "Error reading MFT file record." }
        
# Parse MFT's attributes from file record
$Attributes = New-object byte[]($AttributesRealSize - $OffsetToAttributes)
[Array]::Copy($MftFileRecord, $OffsetToAttributes, $Attributes, 0, $Attributes.Length)
        
# Find Data attribute
$CurrentOffset = 0
do {
    $AttributeType = [Bitconverter]::ToInt32($Attributes[$CurrentOffset..$($CurrentOffset + 3)], 0)
    $AttributeSize = [Bitconverter]::ToInt32($Attributes[$($CurrentOffset + 4)..$($CurrentOffset + 7)], 0)
    $CurrentOffset += $AttributeSize
} until ($AttributeType -eq 128)
        
# Parse data attribute from all attributes
$DataAttribute = $Attributes[$($CurrentOffset - $AttributeSize)..$($CurrentOffset - 1)]

# Parse MFT size from data attribute
$MftSize = [Bitconverter]::ToUInt64($DataAttribute[0x30..0x37], 0)
        
# Parse data runs from data attribute
$OffsetToDataRuns = [Bitconverter]::ToInt16($DataAttribute[0x20..0x21], 0)        
$DataRuns = $DataAttribute[$OffsetToDataRuns..$($DataAttribute.Length -1)]
        
# Convert data run info to string[] for calculations
$DataRunStrings = ([Bitconverter]::ToString($DataRuns)).Split('-')
        
# Setup to read MFT
$FileStreamOffset = 0
$DataRunStringsOffset = 0        
$TotalBytesWritten = 0
$MftData = New-Object byte[](0x1000)
$OutputFileStream = [IO.File]::OpenWrite($OutputFilePath)

do {
    $StartBytes = [int]($DataRunStrings[$DataRunStringsOffset][0]).ToString()
    $LengthBytes = [int]($DataRunStrings[$DataRunStringsOffset][1]).ToString()
            
    $DataRunStart = "0x"
    for ($i = $StartBytes; $i -gt 0; $i--) { $DataRunStart += $DataRunStrings[($DataRunStringsOffset + $LengthBytes + $i)] }

    $DataRunLength = "0x"
    for ($i = $LengthBytes; $i -gt 0; $i--) { $DataRunLength += $DataRunStrings[($DataRunStringsOffset + $i)] }

    $FileStreamOffset += ([int]$DataRunStart * 0x1000)
    $FileStream.Position = $FileStreamOffset           

    for ($i = 0; $i -lt [int]$DataRunLength; $i++) {
        if ($FileStream.Read($MftData, 0, $MftData.Length) -ne $MftData.Length) { 
            Write-Warning "Possible error reading MFT data on $env:COMPUTERNAME." 
        }
        $OutputFileStream.Write($MftData, 0, $MftData.Length)
        $TotalBytesWritten += $MftData.Length
    }
    $DataRunStringsOffset += $StartBytes + $LengthBytes + 1
} until ($TotalBytesWritten -eq $MftSize)
        
$FileStream.Dispose()
$OutputFileStream.Dispose()

$Properties = @{
    NetworkPath = "$CSV"
    ComputerName = $env:COMPUTERNAME
    'MFT Size' = "$($MftSize / 1024 / 1024) MB"
    'MFT Volume' = $Volume
    'MFT File' = $OutputFilePath
}
New-Object -TypeName PSObject -Property $Properties


[GC]::Collect()
$ScriptTime.Stop()
Write-Verbose "Done, execution time: $($ScriptTime.Elapsed)"