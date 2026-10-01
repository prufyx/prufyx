from tuf.ngclient import Updater

updater = Updater(
    metadata_dir="/private/operator/metadata",
    metadata_base_url="https://metadata.example.invalid/",
)
