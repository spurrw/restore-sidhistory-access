<# Made to fix file ACLs when the SIDHistory AD attribute for some users/groups is removed
    from Active Directory.
    
    Attributes:
    - fsFolder = folder root to search from for orphaned SIDs

    - sidFile = file containing username-SID mapping for deleted SIDHistory values.
        You can add multiple lines for each user if that user had multiple SIDHistory SIDs.

    Once you have your deleted SIDs, prepare a data file like formatted like 
    the example datafile "example-missing-sids.txt":
    user1 -------- {SID}
    user2 -------- {SIDa}
    user2 -------- {SIDb}
    ...
    userx -------- {SID}

    - addACEs = Set to true to, when it finds an orphaned SID on a file ACL that's also
        present in $sidFile, to add that current username's AD SID on with the same
        access level as the orphaned SID

    - removeACEs = Set to true to, when you add a new SID with the addACEs option, to
        remove the orphaned SID from the ACL. It doesn't remove orphaned SID ACEs if
        it can't match the SID to one in $sidFile

#>

param(
    [Parameter(Mandatory=$true)]
    [string] $fsFolder,

    [Parameter(Mandatory=$true)]
    [string] $sidFile,

    [bool] $addACEs = $false,

    [bool] $removeACEs = $false
  )

$date = Get-Date
$timeString = "$($date.Year)-$($date.Month)-$($date.Day) $($date.Hour)-$($date.Minute)-$($date.Second)"
Start-Transcript ".\$timeString-sid-audit.ps1.log"

If (-not (Test-Path $fsFolder)) {
    Write-Host "$fsFolder doesn't exist"
    exit
}

If (-not (Test-Path $sidFile)) {
    Write-Host "$sidFile doesn't exist"
    exit
}

# retrieve user SIDs
Write-Host "Reading users and SIDs..."
$userSIDs = @{}
ForEach ($line in Get-Content $sidFile) {
    $user = $line.substring(0, $line.indexOf("--------")).TrimEnd()
    #Write-Host $user

    $line = $line.substring($line.IndexOf("{"))
    $sid = $line.substring($line.IndexOf("{") + 1, $line.IndexOf("}") - 1)
    #Write-Host $sid

    If ($sid -in $userSIDs.Keys) {
        $userSIDs[$sid] += $user
    }
    Else {
        $userSIDs[$sid] = @($user)
    }
    
}

# get file objects to check
Write-Host "Enumerating filesystem of $fsFolder ..."
#$fsObjects = Get-ChildItem $fsFolder -Recurse
Write-Host "FS objects with orphaned SIDs on ACLs...`n`r"

$fsObjectCount = 0
$identifiedFSObjects = @() # objects with orphaned SIDs we identified
$unidentifiedFSObjects = @() # objects with orphaned SIDs we can't identify
#ForEach ($f in $fsObjects) {
Get-ChildItem $fsFolder -Recurse -ErrorAction "Continue" | ForEach-Object {
    try {
   		$item = get-item -literalpath $_.FullName -ErrorAction "Continue"
        $aclAccess = $item.GetAccessControl().Access
    } catch {
        Write-Host "Error: unable to read object ACL $($_)"
#        continue
    }
    $fsObjectCount += 1
    
    # look through ACLs on fs object
    ForEach ($ace in $aclAccess) {
        #Write-Host $acl.IdentityReference
        $aceSID = $ace.IdentityReference.ToString()
        # look for SIDs that aren't inherited (don't muck up output)
        If ($aceSID -like "S-1-*" -and -not $ace.IsInherited) {
            Write-Host $_.FullName
            Write-Host $aceSID

            # match a SID?
            If ($aceSID -in $userSIDs.Keys) {
                Write-Host "--$($userSIDs[$aceSID])"
                $identifiedFSObjects += "$($_.FullName) - $($userSIDs[$aceSID])"

                # replace orphaned SID
                If ($addACEs) {
                    Write-Host "---Attempting to add orphaned user back on..."
                    $newIdentityReference = "$($userSIDs[$aceSID])"
                    Write-Host "---New Identity Refence: $newIdentityReference"
                    $newACE = New-Object System.Security.AccessControl.FileSystemAccessRule (
                        $newIdentityReference,
                        $ace.FileSystemRights,
                        $ace.InheritanceFlags,
                        $ace.PropagationFlags,
                        $ace.AccessControlType
                    )

                    # create and set ACL for file
                    try {
                        $acl.AddAccessRule($newACE)
                        # remove orphaned SID
                        If ($removeACEs) {
                            Write-Host "---Removing orphaned SID"
                            $acl.RemoveAccessRule($ace)
                        }

                        Set-Acl -Path $_.FullName -AclObject $acl
                        Write-Host '---ACL change successful'
                    } catch {
                        Write-Host "---ERROR: Cannot set ACL on $($_.FullName)"
                        Write-Host $_
                    }
                }

            }
            # get possible matches from partial SIDs
            Else {
                Write-Host "--SID not identified"
                $unidentifiedFSObjects += "$($_.FullName) - $aceSID"
                ForEach ($userSID in $userSIDs.Keys) {
                    If ($aceSID -like "$userSID*") {
                        Write-Host "---Possible SID match with $($userSIDs[$userSID])"
                    }
                }
            }
            Write-Host
        }
    }
}

Write-Host "Read ACLs successfully of $fsObjectCount filesystem objects"
$identifiedFSObjects > ".\$timeString-FS objects with identified SIDs.txt"
$unidentifiedFSObjects > ".\$timeString-FS objects with unidentified SIDs.txt"

Stop-Transcript
