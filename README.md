## hackScanner

集成常见web漏洞扫描和网页爬虫

如果出现依赖不存在

```
pip install -r requirements.txt
```



#### 0x01 runserver

本平台使用Django架构，启动需要切换到`manage.py`目录下，在终端输入

```
python manage.py runserver
```

Django会在本地`127.0.0.1:8000`启动服务



#### 0x02 scanner

扫描器，多线程扫描指定url的前端代码，根据后缀判断类型

扫描文件内容，使用正则匹配，匹配模式默认写在`pattern.xml`，可通过修改`pattern.xml`文件修改或增加漏洞特征

使用：

依照页面提示输入url和线程数，脚本会开始爬取网站前端代码资源，将资源爬完后存储到本地，开始扫描路径下文件，扫描完毕返回结果，删除下载到本地的资源

可以点击`Download report`下载扫描结果报告，或者点击`Send to email`将报告结果推送到邮箱



