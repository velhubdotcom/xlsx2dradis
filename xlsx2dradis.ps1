
Param(
[Parameter(Mandatory=$true)][string]$File
)

# Para evitar que revise el certificado
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

$url = "https://ip"
$api = '/pro/api'

# API Key
$token = 'eaea'
# Cambiar Project-Id
$project = "6"

$headers = @{
    "Authorization" = "Token $token"
    "Dradis-Project-Id" = $project
}

$hosts = @()
$issues = Import-Excel $File -WorksheetName "Issues"
$uploaded = @()

# Lista los hosts en el excel
foreach ($issue in $issues) {
  If ($issue.Host -And -not ($hosts -contains $issue.Host)){
     $hosts += $issue.Host
  }
}

foreach ($ip_add in $hosts) {

    # Crea el host en dradis

    $endpoint = '/nodes'

    $node = @{
        label = $ip_add
        type_id = 1
        parent_id = $null
        position = 1
    }

    $body = @{
        node = $node
    }

    $json = $body | ConvertTo-Json
    $encoded = [System.Text.Encoding]::UTF8.GetBytes($json)
    $response = Invoke-RestMethod -Method Post -Uri $url$api$endpoint -Headers $headers -Body $encoded -ContentType "application/json"
    $nodeId = $response[0].id

    $counter = 0
    foreach ($issue in $issues) {

        # Agrega los issues de cada host        

        if (($ip_add -eq $issue.Host) -And -not ($uploaded -contains $counter)){

            $endpoint = '/issues'

            $text = @{
                text = -join("#[Title]#`r`n", $issue.Vulnerabilidad, "`r`n`r`n#[CVSSv3.BaseScore]#`r`n", $issue.CVSSv3 ,"`r`n`r`n#[CVSSv3Vector]#`r`n", $issue.Vector, "`r`n`r`n#[Type]#`r`n", $issue.Tipo, "`r`n`r`n#[Description]#`r`n", $issue.Descripcion, "`r`n`r`n#[References]#`r`n", "N/A", "`r`n`r`n#[Category]#`r`n", "N/A", "`r`n`r`n#[Access]#`r`n", "Remoto", "`r`n`r`n#[Risk]#`r`n", $issue.Criticidad, "`r`n`r`n#[CWE]#`r`n", $issue.CWE, "`r`n`r`n#[CAPEC]#`r`n", $issue.CAPEC, "`r`n`r`n#[OWASP]#`r`n", $issue.OWASP, "`r`n`r`n#[DescriptionShort]#`r`n", "N/A", "`r`n`r`n#[Impact]#`r`n", $issue.Impacto, "`r`n`r`n#[Likelihood]#`r`n", "N/A", "`r`n`r`n#[Remediation]#`r`n", $issue.Recomendacion, "`r`n`r`n#[Enhancement]#`r`n", "N/A", "`r`n`r`n#[Tier]#`r`n", "N/A", "`r`n`r`n#[Ease]#`r`n", "N/A", "`r`n`r`n#[Magnitude]#`r`n", "N/A", "`r`n`r`n#[plugin_id]#`r`n", $issue.ID)
            }

            $body = @{
                issue = $text
            }

            $json = $body | ConvertTo-Json
            $encoded = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response = Invoke-RestMethod -Method Post -Uri $url$api$endpoint -Headers $headers -Body $encoded -ContentType "application/json"
            $issueId = $response[0].id

            # Agrega la ubicacion de cada issue con el mismo ID
            $internal_counter = 0
            foreach ($vuln in $issues) {

                if (($vuln.ID -eq $issue.ID) -And ($vuln.Host -eq $ip_add)){

                    $endpoint = -join('/nodes/', $nodeId, "/evidence")

                    $evidence = @{
                        content = -join("#[Location]#`r`n", $vuln.Ubicacion, "`r`n`r`n#[Output]#`r`n", "N/A")
                        issue_id = $issueId
                    }

                    $body = @{
                        evidence = $evidence
                    }

                    $json = $body | ConvertTo-Json
                    $encoded = [System.Text.Encoding]::UTF8.GetBytes($json)
                    $response = Invoke-RestMethod -Method Post -Uri $url$api$endpoint -Headers $headers -Body $encoded -ContentType "application/json"
                    $uploaded += $internal_counter
                }
                $internal_counter++
            }
        }
        $counter++
    }
}
