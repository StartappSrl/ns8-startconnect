*** Settings ***
Library    SSHLibrary

*** Variables ***
${ADMIN_USER}    admin
${ADMIN_PASSWORD}    Nethesis,1234
${module_id}    ${EMPTY}
${LDAP_DOMAIN}    ad.test

*** Keywords ***
Login to cluster-admin
    New Page    https://${NODE_ADDR}/cluster-admin/
    Fill Text    text="Username"    ${ADMIN_USER}
    Click    button >> text="Continue"
    Fill Text    text="Password"    ${ADMIN_PASSWORD}
    Click    button >> text="Log in"
    Wait For Elements State    css=#main-content    visible    timeout=10s

Backend answers
    ${output}    ${rc} =    Execute Command    curl -sS -f -H 'Host: startconnect.test' http://127.0.0.1/api/info
    ...    return_rc=True
    Log    ${output}
    Should Be Equal As Integers    ${rc}  0

Log module state
    ${output} =    Execute Command    curl -sS -i -H 'Host: startconnect.test' http://127.0.0.1/api/info; runagent -m ${module_id} systemctl --user --no-pager status startconnect.service startconnect-app.service guacd.service; runagent -m ${module_id} journalctl --user --no-pager -n 60
    Log    ${output}    console=True

*** Test Cases ***
Check if startconnect is installed correctly
    ${output}  ${rc} =    Execute Command    add-module ${IMAGE_URL} 1
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0
    &{output} =    Evaluate    ${output}
    Set Global Variable    ${module_id}    ${output.module_id}

Take screenshots
    [Tags]    ui
    Import Library    Browser
    New Browser    chromium    headless=True
    New Context    ignoreHTTPSErrors=True
    Login to cluster-admin
    Go To    https://${NODE_ADDR}/cluster-admin/#/apps/${module_id}
    Wait For Elements State    iframe >>> h2 >> text="Status"    visible    timeout=10s
    Sleep    5s
    Take Screenshot    filename=${OUTPUT DIR}/browser/screenshot/1._Status.png
    Go To    https://${NODE_ADDR}/cluster-admin/#/apps/${module_id}?page=settings
    Wait For Elements State    iframe >>> h2 >> text="Settings"    visible    timeout=10s
    Sleep    5s
    Take Screenshot    filename=${OUTPUT DIR}/browser/screenshot/2._Settings.png
    Close Browser

Check if startconnect can be configured
    ${rc} =    Execute Command    api-cli run module/${module_id}/configure-module --data '{"host": "startconnect.test", "http2https": false, "lets_encrypt": false, "ldap_domain": "${LDAP_DOMAIN}", "admin_group": "domain admins"}'
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0

Check if startconnect works as expected
    # Dopo configure-module il backend e la rotta Traefik impiegano qualche secondo ad attivarsi
    Wait Until Keyword Succeeds    24 times    5 seconds    Backend answers
    [Teardown]    Run Keyword If Test Failed    Log module state

Check if startconnect is removed correctly
    ${rc} =    Execute Command    remove-module --no-preserve ${module_id}
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0
