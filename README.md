## hackScanner

Integrate common web vulnerability scanning and web crawler

If dependency does not exist

```
pip install -r requirements.txt
```



#### 0x01 runserver

This platform uses the Django architecture, you need to switch to the `manage.py` directory to start, and enter in the terminal

```
python manage.py runserver
```

DDjango will start service locally at `127.0.0.1:8000`


#### 0x02 scanner

Scanner, multi-threaded and scanning front-end code of the specified url, Judge the type according to the suffix

Scan the content of the file and use regular matching. The matching pattern is written in `pattern.xml` by default. You can modify or add vulnerability features by modifying the `pattern.xml` file

use:

Enter url and number of threads according to the prompts on the page, and the script will start to crawl the front-end code resources of the website, store the resources locally after crawling, start scanning the files under the path, return the results after scanning, and delete the resources downloaded locally

You can click `Download report` to download the scan result report, or click `Send to email` to push the report result to the mailbox



