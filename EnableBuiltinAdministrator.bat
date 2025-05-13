::  It is recommended to test the script on a local machine for its purpose and effects. 
::  ManageEngine Desktop Central will not be responsible for any 
::  damage/loss to the data/setup based on the behavior of the script.

::  Description - Script to Enable Built in Administrator account
::  Parameters -  <password> - optional
::  Remarks -     Giving password here will be plain text in Server-Agent Communication. So, we recommend to use User Management configuration to change password
::  Configuration Type - COMPUTER
::  ============================================================================================================================
@echo off
net user Administrator /active:yes
net user Administrator /fullname:"Gainwell Administrator"
net user Administrator %1