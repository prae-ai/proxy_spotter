# Proxy Spotter

## About

This repository is a template that shows how to use a [mitmproxy Addon script](https://docs.mitmproxy.org/stable/addons-overview/) to gather specified content and inserting a structured HTML object into a [Delta table](https://docs.delta.io/latest/quick-start.html). The intention here is to [clone the repo]() and make it yours locally or [fork the repo]() for using with a group or organization.

This technique could certainly be extended, so if there are improvements to the template version of this repository, submit an Issue and this can be added.

<img width="1671" alt="Screenshot 2024-11-26 at 12 55 32" src="https://github.com/user-attachments/assets/63327fa5-8f4e-4f7c-850f-bf0d10b5daf7">

## Configuration

There are four main things that need to be configured before running the script.

### 1. Dependencies

There are three main dependencies, `mitmproxy`, `pandas`, and `deltalake`, which should be accounted for running `python -m pip install -r requirements.txt`.

### 2. Target URLs

While keeping these in an importable fashion for portability could be done, `mitmproxy` has the ability to reload the script as it changes while it runs. This allows for adding URLs while browsing, without having to stop the utility, update the import file, and re-run. Also, managing escape characters in external files that get imported has challenges, so in the interest of simplicity, this is a simple dictionary inside the main script.

### 3. Follow-On Actions

This script currently saves to a local Delta table, where it attempts to first write to `~/Downloads`. However, this table could be replicated to cloud storage (Azure, AWS, Google Cloud) by adding an event hook on [`done`](https://docs.mitmproxy.org/stable/api/events.html#LifecycleEvents.done) to push results to cloud(s). For example, the following could be added to insert into a table on Azure:

```
from deltalake import DeltaTable
from deltalake.writer import write_deltalake

...

class ProxySpotter:
...
    def done(self) -> None:
        try:
            current_df = DeltaTable(self.data_path).to_pandas()
            # Drop any odd written columns and order
            current_df = DataFrame(current_df, columns=['uuid','datetime','url','status','body'])
            # Force types
            current_df = current_df.astype({'status': 'int32'})
            logging.info(f'[+ {type(self).__name__}] Writing results to proxy_html.delta on Azure Blob')
            write_deltalake(
                'abfss://blob@blobcontainer.dfs.core.windows.net/proxy_html.delta',
                current_df, mode='append', 
                storage_options={'sas_token': 'YOURSASTOKENFROMAZURE'}
            )
            logging.info(f'[+ {type(self).__name__}] Results written to proxy_html.delta on Azure Blob')
        except Exception as e:
            logging.error(f'[- {type(self).__name__}] Problem ingesting {self.data_path}')
            print(e)
            pass
```

### 4. Logging

Configure the log output path in `FileLog` for any debugging of target domains and/or urls, or errors in the script.

## Running

1) Clone the repository.
2) Configure as explained above in [Configuration]()
3) Run mitmproxy with the script option: `mitmproxy -s proxy_spotter.py`

![proxy_spotter](https://github.com/user-attachments/assets/8f603c57-4cd3-40dc-be43-7f3f9e6191d1)

## Adding Sources

Simply add the domain and url pattern to match to the `TARGET_URLS` dictionary, then browse to a matching url.
