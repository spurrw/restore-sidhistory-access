== Background ==

Active Directory users have an attribute called SIDHistory. It contains SIDs
used in domains that users were migrated from during a domain migration. You
cannot manually write to this value, it can only be set during a domain
migration. In a domain I manage I thought I'd clear this value out from the
many users that had it set from domain migrations around 10 years previous. We
thought this shouldn't break anything and is recommended by security auditors.
Before doing so I exported all the SIDHistory values that were going to be
deleted and then deleted this attribute for all users and groups containing it.

== Problem ==

The next day we discover some users can't access files on their network drives.
They're granted access to these files/folders (which are SUPER old but important)
because they're being granted access via their old SID from now-dead AD domains.
I see no big deal, I can do the following:
- look at the SIDs that I deleted and restore them to user accounts that need it

Only problem is you can't write to SIDHistory manually, which I didn't know.
Also, when I exported the deleted SIDs I didn't notice that PowerShell trimmed
the values to make things look "pretty". So I don't have the old SIDs and I
couldn't restore them even if I did.

== Solution ==

I had to do the following to get people access to their files:

1. Query a backup of NTDS.dit (AD database) from a domain controller to get the
    deleted SIDs
2. Write a script to comb a directory structure and look for any of the deleted
    SIDs on file ACLs. I gave the script the option to repair the orphaned SIDs
    with the user's SID from the current AD domain

This tells you how to do that in case you break things like I did!

==== Restoring SIDs or other AD Attributes ====

== Query a backup of NTDS.dit ==

I owe this section to this post: https://dxpetti.com/blog/2020/mounting-an-active-directory-database-backup/
I've shortened the process here.

1. Retrieve Old Database
    a. Get a backup of a domain controller's filesystem somehow or a running version
        of it not connected to the network.
    b. Login to the backup DC
    c. Copy the AD database located at C:\Windows\NTDS\ntds.dit
    d. If DC services are running you can't just copy a normal way, because the file is
        locked: https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds
    e. Try copying this way:
        ntdsutil "activate instance ntds" "ifm" "create full C:\Windows\Temp\NTDS" quit quit
        Copy the files named like "edb*" from C:\Windows\NTDS if you can
        Copy ntds.dit and the edb files onto a working domain controller
    f. Alternatively, just mount the DC's drive on another secure computer and copy the
        files that way.
Remember, don't restore network to a backup of a DC!


== Verify Database ==

1. Get ntds.dit and the edb files onto a working domain controller
2. Commit pending changes from edb files to ntds.dit (if you got the edb files):
    esentutl /r edb
3. Perform integrity check on the database:
    esentutl /g ntds.dit
4. Repair the database if needed:
    esentutl /p ntds.dit

== Mount Database ==

1. Mount the database for querying and chose a port number to have it listen on (777 in this case):
    dsamain /dbpath ntds.dit /ldapport 777
2. Open up your firewall (to the extent desired) to allow connections on TCP port 777

== Query Database ==

1. You can now query the old AD database just like any production AD database
    running on your production DCs. You just need to specify a port number to connect to it on:
    Get-ADUser -Identity jeff -Server dc1.contoso.com:777


==== Repairing File ACLs with the Script ====

1. Once you have your deleted SIDs, prepare a data file like formatted like 
    the example datafile "example-missing-sids.txt":
    user1 -------- {SID}
    user2 -------- {SID}
    ...
    userx -------- {SID}

If you don't like this format you can change how the script parses the file.
This was the parsing I used to fix this quickly.

2. Run the script like this to audit file permissions issues in PowerShell.
    You can skip this step and go straight to using a "fix" mode in the next step:
    .\sid-audit.ps1 -fsFolder E:\ -sidFile .\sids.txt
    It creates a couple files as output to tell what it found:
    .\$(timestamp)-FS objects with identified SIDs.txt
        - files/folders where an orphaned SID was matched
    .\$(timestamp)-FS objects with identified SIDs.txt
        - files/folders where an orphaned SID was not matched
        - if you have all SIDs you deleted you can ignore this file

3. Run the script in one of two "fix" modes to fix the ACLs
    .\sid-audit.ps1 -fsFolder E:\ -sidFile .\sids.txt -addACEs:$true
        - add removed users/groups to the ACL

    .\sid-audit.ps1 -fsFolder E:\ -sidFile .\sids.txt -addACEs:$true -removeACEs:$true
        - add removed users/groups to the ACL
        - remove orphaned SIDs that are identified and replaced

Once you run the script in a "fix" mode it will fix your file ACLs and give users/groups
access to their files again! This, of course, assumes you have access to read and modify
their file ACLs.
