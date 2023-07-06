<?php
function installWireGuard()
{
    $output = '';

    // Install dependencies
    $command1 = "sudo apt-get install -y wget";
    $output .= shell_exec($command1);

    // Download the setup script
    $command2 = "sudo wget -O wireguard.sh https://get.vpnsetup.net/wg";
    $output .= shell_exec($command2);

    // Execute the downloaded script with automatic mode
    $password = "postcard";
    $command3 = 'echo "' . $password . '" | sudo -S bash wireguard.sh --auto';
    $output .= shell_exec($command3);

    return $output;
}

