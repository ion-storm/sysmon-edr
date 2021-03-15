Function Stop-Thread {
    <#
        .SYNOPSIS
            This function is used to terminate a thread on a given process.

        .DESCRIPTION
            This function is used to terminate a thread on a given process.

            IMPORTANT!!!
            Terminating threads can potentially lead to bigger issues with a process
            such as corrupting the process or introducing memory leaks. Make sure that
            you understand what will happen when terminating a thread that you did not
            build.

        .PARAMETER ThreadID
            The thread ID on a given process to terminate.

        .NOTES
            Name: Stop-Thread
            Author: Boe Prox
            Version History:
                1.0 //Boe Prox - 12/17/2015
                    - Initial build

        .EXAMPLE
            #Review PowerShell process threads
            (Get-Process PowerShell).Threads | Format-Table

            #Pick a thread to remove
            Stop-Thread -ThreadID 6376

            Description
            -----------
            Terminates a thread on the PowerShell process

        .EXAMPLE
            #Open notepad process and get ThreadIds
            Start-Process Notepad

            #Stop the ThreadID
            (Get-Process Notepad).Threads.Id | Stop-Thread -Verbose

            VERBOSE: Performing the operation "Terminate thread" on target "4360".

            Description
            -----------
            Stops notepad completely as it only has a single thread.
    #>
    [cmdletbinding(SupportsShouldProcess = $True)]
    Param (
        [parameter(ValueFromPipeline=$True)]
        [intptr[]]$ThreadID
    )
    Begin {
        Try {
            [void][ThreadStop]
        } Catch {
            Write-Verbose "Building pinvoke via reflection"
            #region Module Builder
            $Domain = [AppDomain]::CurrentDomain
            $DynAssembly = New-Object System.Reflection.AssemblyName('ThreadStop')
            $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run) # Only run in memory
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('ThreadStop', $False)
            #endregion Module Builder

            #region ENUMs
            #region LSA_AccessPolicy
            $EnumBuilder = $ModuleBuilder.DefineEnum('ThreadAccess', 'Public', [uint32])
            [void]$EnumBuilder.DefineLiteral('TERMINATE', [uint32] 0x0001)
            [void]$EnumBuilder.DefineLiteral('SUSPEND_RESUME', [uint32] 0x0002)
            [void]$EnumBuilder.DefineLiteral('GET_CONTEXT', [uint32] 0x0008)
            [void]$EnumBuilder.DefineLiteral('SET_CONTEXT', [uint32] 0x0010)
            [void]$EnumBuilder.DefineLiteral('SET_INFORMATION', [uint32] 0x0020)
            [void]$EnumBuilder.DefineLiteral('QUERY_INFORMATION', [uint32] 0x0040)
            [void]$EnumBuilder.DefineLiteral('SET_THREAD_TOKEN', [uint32] 0x0080)
            [void]$EnumBuilder.DefineLiteral('IMPERSONATE', [uint32] 0x0100)
            [void]$EnumBuilder.DefineLiteral('DIRECT_IMPERSONATION', [uint32] 0x0200)
            [void]$EnumBuilder.CreateType()
            #endregion LSA_AccessPolicy
            #endregion ENUMs

            $TypeBuilder = $ModuleBuilder.DefineType('ThreadStop', 'Public, Class')

            #region METHODS
            #region OpenThread Method
            $PInvokeMethod = $TypeBuilder.DefineMethod(
                'OpenThread', #Method Name
                [Reflection.MethodAttributes] 'PrivateScope, Public, Static, HideBySig, PinvokeImpl', #Method Attributes
                [uint32], #Method Return Type
                [Type[]] @(
                    [int32],  #Desired Access
                    [bool],   #Inherit Handle
                    [int32]   #Thread ID
                ) #Method Parameters
            )

            $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
            $FieldArray = [Reflection.FieldInfo[]] @(
                [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
                [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
                [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig')
                [Runtime.InteropServices.DllImportAttribute].GetField('CharSet')
            )

            $FieldValueArray = [Object[]] @(
                'OpenThread', #CASE SENSITIVE!!
                $True,
                $True,
                [System.Runtime.InteropServices.CharSet]::Auto
            )

            $CustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
                $DllImportConstructor,
                @('kernel32.dll'),
                $FieldArray,
                $FieldValueArray    
            )

            $PInvokeMethod.SetCustomAttribute($CustomAttribute)
            #endregion OpenThread Method
            #region TerminateThread Method
            $PInvokeMethod = $TypeBuilder.DefineMethod(
                'TerminateThread', #Method Name
                [Reflection.MethodAttributes] 'PrivateScope, Public, Static, HideBySig, PinvokeImpl', #Method Attributes
                [uint32], #Method Return Type
                [Type[]] @(
                    [intptr], #Thread
                    [int32]   #ExitCode

                ) #Method Parameters
            )

            $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
            $FieldArray = [Reflection.FieldInfo[]] @(
                [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
                [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
                [Runtime.InteropServices.DllImportAttribute].GetField('ExactSpelling')
                [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig')
            )

            $FieldValueArray = [Object[]] @(
                'TerminateThread', #CASE SENSITIVE!!
                $True,
                $True,
                $True
            )

            $CustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
                $DllImportConstructor,
                @('kernel32.dll'),
                $FieldArray,
                $FieldValueArray
            )

            $PInvokeMethod.SetCustomAttribute($CustomAttribute)
            #endregion TerminateThread Method
            #region CloseHandle Method
            $PInvokeMethod = $TypeBuilder.DefineMethod(
                'CloseHandle', #Method Name
                [Reflection.MethodAttributes] 'PrivateScope, Public, Static, HideBySig, PinvokeImpl', #Method Attributes
                [bool], #Method Return Type
                [Type[]] @(
                    [intptr] #Handle
                ) #Method Parameters
            )

            $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
            $FieldArray = [Reflection.FieldInfo[]] @(
                [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
                [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
                [Runtime.InteropServices.DllImportAttribute].GetField('ExactSpelling')
                [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig')
            )

            $FieldValueArray = [Object[]] @(
                'CloseHandle', #CASE SENSITIVE!!
                $True,
                $True,
                $True
            )

            $CustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
                $DllImportConstructor,
                @('kernel32.dll'),
                $FieldArray,
                $FieldValueArray
            )

            $PInvokeMethod.SetCustomAttribute($CustomAttribute)
            #endregion CloseHandle Method
            #endregion METHODS

            [void]$TypeBuilder.CreateType()
        }    
        $CurrentThread = [appdomain]::GetCurrentThreadId()
        $ExitCode = 1
    }
    Process {
        ForEach ($Thread in $ThreadID) {
            If ($Thread -eq $CurrentThread) {
                Write-Warning "Skipping ThreadID: $($Thread) as it is the current thread."
                Continue
            } Else {
                $Handle = [ThreadStop]::OpenThread([ThreadAccess]::TERMINATE, $False, $Thread)
                If ($Handle -gt 0) {
                    If ($PSCmdlet.ShouldProcess($Thread,'Terminate thread')) {
                        Try {
                            $Return = [ThreadStop]::TerminateThread($Handle, $ExitCode)
                            If ($Return -eq 0) {
                                Write-Warning "Unable to close Thread: $($Thread)!"
                            }
                        } Catch {
                            Write-Warning $_
                        }
                    }
                    [void][ThreadStop]::CloseHandle($Handle)
                } Else {
                    Write-Warning "Couldn't open or find Thread ID: $($Thread)!"
                }
            }
        }
    }
}