import { TargetName } from './autodiscovery-script.types';

export function getAutodiscoveryScriptTargetNameScript(targetName: TargetName): string {
    switch (targetName.scheme) {
    case 'digitalocean':
        return 'TARGET_NAME=$(curl http://169.254.169.254/metadata/v1/hostname)';
    case 'aws':
        return String.raw`
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
TARGET_NAME=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)`;
    case 'time':
        return 'TARGET_NAME=target-$(date +"%m%d-%H%M%S")';
    case 'hostname':
        return 'TARGET_NAME=$(hostname)';
    case 'manual':
        return `TARGET_NAME=\"${targetName.name}\"`;
    default:
        // Compile-time exhaustive check
        const _exhaustiveCheck: never = targetName;
        return _exhaustiveCheck;
    }
}