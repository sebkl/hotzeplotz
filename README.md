# hotzeplotz

Warning: WIP

Tools and scripts to automate home network infrastructure, including Dynamic DNS (DDNS) record updates in Google Cloud DNS via Google Cloud Functions.

## Configuration

To configure project IDs, domains, tokens, and deployment targets, create a local `config.mk` file from the provided example:

```bash
cp config.mk.example config.mk
```

Edit the `config.mk` and adjust settings accrodingly and make sure all variables are set.

## Deployment
Deploy both the client update script to your target device and the Cloud Function to GCP:
```bash
make deploy
```

## TODO

*  Make the token secure and actually use it.
*  Cleanup AI nonesense.
*  Add infrastructure to allow certain secrets only to update certain hostnames (plural).
