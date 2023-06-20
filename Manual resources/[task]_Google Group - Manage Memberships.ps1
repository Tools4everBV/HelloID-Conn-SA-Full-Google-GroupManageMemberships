#variables
$groupId = $form.gridGroups.Id
$groupName = $form.gridGroups.name
$usersToAdd = $form.members.leftToRight
$usersToRemove = $form.members.rightToLeft

#region Support Functions
function Get-GoogleAccessToken() {
    ### exchange the refresh token for an access token
    $requestUri = "https://www.googleapis.com/oauth2/v4/token"
        
    $refreshTokenParams = @{
            client_id=$GoogleClientId;
            client_secret=$GoogleClientSecret;
            redirect_uri=$GoogleRedirectUri;
            refresh_token=$GoogleRefreshToken;
            grant_type="refresh_token"; # Fixed value
    };
    $response = Invoke-RestMethod -Method Post -Uri $requestUri -Body $refreshTokenParams -Verbose:$false
    $accessToken = $response.access_token
            
    #Add the authorization header to the request
    $authorization = [ordered]@{
        Authorization = "Bearer $($accesstoken)";
        'Content-Type' = "application/json; charset=utf-8";
        Accept = "application/json";
    }
    $authorization
}
#endregion Support Functions

#region Execute
    #Add the authorization header to the request
    $authorization = Get-GoogleAccessToken

    $usersToAddJson =  $usersToAdd | ConvertFrom-Json
    $usersToRemoveJson =  $usersToRemove | ConvertFrom-Json

    Write-Information "Users to add: $($usersToAdd.email)"
    Write-Information "Users to remove: $($usersToRemove.email)" 

    foreach($user in $usersToAddJson)
    {
        try {
        Write-Information "Starting to add Google group [$($groupName)] to Google user $($user.email)"
        
        $account = [PSCustomObject]@{
            email = $user.email
            role = "MEMBER"
        }

        $splat = @{
            Uri = "https://www.googleapis.com/admin/directory/v1/groups/$($groupId)/members" 
            Body = [System.Text.Encoding]::UTF8.GetBytes(($account | ConvertTo-Json))
            Method = 'POST'
            Headers = $authorization
        }

        $response = Invoke-RestMethod @splat
   
        Write-Information "Finished adding Google group [$($groupName)] to Google user $($user.email)"
        $Log = @{
            Action            = "AddMembers" # optional. ENUM (undefined = default) 
            System            = "Google" # optional (free format text) 
            Message           = "Successfully added Google group [$($groupName)] to Google user $($user.email)" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $($user.email) # optional (free format text) 
            TargetIdentifier  = $groupName # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
        
        }
        catch {
            Write-Information "Could not add Google group [$($groupName)] to Google user $($user.email). Error: $($_.Exception.Message)"
            $Log = @{
                Action            = "AddMembers" # optional. ENUM (undefined = default) 
                System            = "Google" # optional (free format text) 
                Message           = "Failed to add Google Google [$($groupName)] to Google user $($user.email)" # required (free format text) 
                IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $($user.email) # optional (free format text) 
                TargetIdentifier  = $groupName # optional (free format text) 
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
        }
    }

    foreach($user in $usersToRemoveJson)
    {
        try {
        Write-Information "Starting to remove Google group [$($groupName)] to Google user $($user.email)"
        
        $splat = @{
            Uri = "https://www.googleapis.com/admin/directory/v1/groups/$($groupId)/members/$($user.email)"
            Method = 'DELETE'
            Headers = $authorization
        }
        $response = Invoke-RestMethod @splat

        Write-Information "Finished removing Google group [$($groupName)] to Google user $($user.email)"
        $Log = @{
            Action            = "RemoveMembers" # optional. ENUM (undefined = default) 
            System            = "Google" # optional (free format text) 
            Message           = "Successfully removed Google group [$($groupName)] from Google user $($user.email)" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $($user.email) # optional (free format text) 
            TargetIdentifier  = $groupName # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log

        }
        catch {          
            Write-Information "Could not remove Google group [$($groupName)] to Google user $($user.email). Error: $($_.Exception.Message)"
            $Log = @{
                Action            = "RemoveMembers" # optional. ENUM (undefined = default) 
                System            = "Google" # optional (free format text) 
                Message           = "Failed to remove Google group [$($groupName)] from Google user $($user.email)" # required (free format text) 
                IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $($user.email) # optional (free format text) 
                TargetIdentifier  = $groupName # optional (free format text) 
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
        }
    }
#endregion Execute
