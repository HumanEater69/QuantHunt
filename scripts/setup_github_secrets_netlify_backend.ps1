Param(
  [Parameter(Mandatory = $true)] [string]$Repo,
  [Parameter(Mandatory = $true)] [string]$NetlifyAuthToken,
  [Parameter(Mandatory = $true)] [string]$NetlifySiteId,
  [Parameter(Mandatory = $true)] [string]$NetlifySiteUrl,
  [Parameter(Mandatory = $true)] [string]$BackendDeployHookUrl,
  [Parameter(Mandatory = $true)] [string]$BackendOrigin
)

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
  throw "GitHub CLI (gh) is required. Install from https://cli.github.com/"
}

Write-Host "Setting repository secrets for $Repo ..."

$NetlifyAuthToken | gh secret set NETLIFY_AUTH_TOKEN --repo $Repo
$NetlifySiteId | gh secret set NETLIFY_SITE_ID --repo $Repo
$NetlifySiteUrl | gh secret set NETLIFY_SITE_URL --repo $Repo
$BackendDeployHookUrl | gh secret set BACKEND_DEPLOY_HOOK_URL --repo $Repo
$BackendOrigin | gh secret set BACKEND_ORIGIN --repo $Repo

Write-Host "Done. Netlify + backend deployment secrets configured for $Repo"
