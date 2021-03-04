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

    HID-Write-Status -Message "Users to add: $($usersToAdd.email)" -Event Information
    HID-Write-Status -Message "Users to remove: $($usersToRemove.email)" -Event Information

    foreach($user in $usersToAddJson)
    {
        try {
        HID-Write-Status -Message "Starting to add Google group [$($groupName)] to Google user $($user.email)" -Event Information
        
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

        HID-Write-Status -Message "Finished adding Google group [$($groupName)] to Google user $($user.email)" -Event Success
        HID-Write-Summary -Message "Successfully added Google group [$($groupName)] to Google user $($user.email)" -Event Success
        }
        catch {
            HID-Write-Status -Message "Could not add Google group [$($groupName)] to Google user $($user.email). Error: $($_.Exception.Message)" -Event Error
            HID-Write-Summary -Message "Failed to add Google Google [$($groupName)] to Google user $($user.email)" -Event Failed
        }
    }

    foreach($user in $usersToRemoveJson)
    {
        try {
        HID-Write-Status -Message "Starting to remove Google group [$($groupName)] to Google user $($user.email)" -Event Information
        
        $splat = @{
            Uri = "https://www.googleapis.com/admin/directory/v1/groups/$($groupId)/members/$($user.email)"
            Method = 'DELETE'
            Headers = $authorization
        }
        $response = Invoke-RestMethod @splat


        HID-Write-Status -Message "Finished removing Google group [$($groupName)] to Google user $($user.email)" -Event Success
        HID-Write-Summary -Message "Successfully removed Google group [$($groupName)] to Google user $($user.email)" -Event Success
        }
        catch {
            HID-Write-Status -Message "Could not remove Google group [$($groupName)] to Google user $($user.email). Error: $($_.Exception.Message)" -Event Error
            HID-Write-Summary -Message "Failed to remove Google Google [$($groupName)] to Google user $($user.email)" -Event Failed
        }
    }
#endregion Execute
