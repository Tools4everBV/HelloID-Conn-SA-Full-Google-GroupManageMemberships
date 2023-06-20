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
$results = [System.Collections.Generic.List[object]]::new()
try {
	#Add the authorization header to the request
	$authorization = Get-GoogleAccessToken

	$parameters = @{
		customer = "my_customer"
	}

	do {
		$splat = @{
		    Uri = ("https://www.googleapis.com/admin/directory/v1/groups/{0}/members" -f $datasource.selectedGroup.id)
			Body = $parameters
			Method = 'GET'
			Headers = $authorization
		}
        
		$response = Invoke-RestMethod @splat 
		$parameters['pageToken'] = $response.nextPageToken;
        
		if($response.members -eq $null) { 
            break;
        }
        elseif($response.members -is [array]) {
            $results.AddRange($response.members);
        }
        else
        {
            $results.Add($response.members);
        }
        
        

	} while ($parameters['pageToken'] -ne $null)
}catch{
    Write-Error "Error: $($_)"
}

Write-Information "Total Members $($results.count)";
#endregion Execute

#region Build up result
#Return Groups
foreach($item in $results)
{
	Write-Output ($item | ConvertTo-Json -Depth 10)
}
#endregion Build up result



