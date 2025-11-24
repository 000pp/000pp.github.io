+++
title = "Attacking Azure Blob Storage Services"
date = 2024-11-22
[taxonomies]
tags = ["azure", "pentest", "microsoft", "web"]
[extra]
+++

Azure, or Microsoft Azure, is a cloud computing platform maintained by Microsoft that offers a bunch of services used by many companies and individuals. Probably, the most famous solutions provided by Microsoft Azure are virtual machines, Azure Kubernetes Services (AKS), solutions for DevOps and DevSecOps, and of course, the giant integration with all other Microsoft services, for example, Active Directory, GitHub, Azure DevOps, Visual Studio, and GitHub Copilot.

Now, what is Azure Blob Storage? Azure Blob Storage is a massively scalable and ~~secure~~ object storage solution for cloud-native workloads, archives, data lakes, HPC, and machine learning (I took this from the Microsoft Azure Blob Storage website). Basically, a lot of companies store their files like videos, documents, executables, logs, backup data, and others in this service and share these resources through their services like web apps, systems, etc.

A Blob Storage is constructed of three types of resources, which are:
- **Storage Account**: A Storage Account is the unique namespace for your Azure data. So, if you store your data on Azure Storage, your data will be available at an address that uses this namespace as the reference for access. Example: `https://000pp.blob.core.windows.net`.

- **Container**: A container is where all the blobs get stored; they work similarly to a directory in a file system. A good thing is there is no limit to how many blobs can be stored in a container, of course, because the purpose is to provide large storage access. A container name can be between 3 and 63 characters long and doesn't support special characters besides the dash character (-).

- **Blob**: A blob is a binary large object and a storage option for any type of data that you want to store in a binary format. (I took this from Microsoft again)

![image](https://learn.microsoft.com/en-us/azure/storage/blobs/media/storage-blobs-introduction/blob1.png)

Azure Blob Storage is basically Microsoft's version of Amazon S3 Bucket or Google Cloud Drive. The main purpose is to serve access to a large scale of files and provide more flexibility in the storing process.

## Why should I know about this?
Well, we're hackers, or pentesters... so we should know about a bunch of things. Today, it is extremely easy to find websites that use Microsoft services/technologies like IIS, ASP.NET, and now, Azure services, like Azure Blob Storage. If we understand the environment that we are fighting in, we know how to find vulnerabilities and create a good report for the client. I have already done a lot of pentests on clients that use Azure Blob Storage and discovered interesting info and sensitive data about the web app, infrastructure, or environment I was attacking with this knowledge.

Now that you understand the importance of knowing what Azure Blob Storage is, we can start talking about the good part: the vulnerabilities that we can find while dealing with this service.

## Anonymous Access
The main advantage of Azure Blobs compared to other Azure artifacts like Azure Files (SMB and REST), Azure Queues, and Azure Tables is that Azure Blobs allow anonymous public read access, as we can see in the image below:

![image](/assets/attacking-azure-blob-storage/azure-services.png)

With anonymous access and the right request, we can enumerate all the blobs (files) inside the target Azure Blob Storage and find really good information. As we said before, the base URL for an Azure Blob Storage is `STORAGE_ACCOUNT_NAME.blob.core.windows.net`, so you need to first discover the Storage Account name. It can be easily discovered if the web app makes a direct request for the file it needs. For example:

![image](/assets/attacking-azure-blob-storage/request.png)

In the image above, before the first dot is the storage account name. If you can't find the storage account this way, I recommend trying three things:
1. Google Dorking

![image](/assets/attacking-azure-blob-storage/google-dorking.png)

2. Use the company's name

![image](/assets/attacking-azure-blob-storage/company.png)

3. Bruteforce with a custom wordlist
Try using FFUF with a custom wordlist that combines the company name and a generic storage name, like `amazoncontent`, `amazonstorage`, `amazonfiles`.

If you can find a valid Azure Blob Storage domain, you're probably going to find a page similar to this:

![image](/assets/attacking-azure-blob-storage/bruteforce.png)

As we can see in the image above, the service is asking for the parameter "comp". If we look at Microsoft's documentation, it says we can enumerate container names using `?comp=list`, but this never worked for me. In an ideal world, like the first image I showed you, the container name will be in the URL. Example: `https://000pp.blob.core.windows.net/static/js/jquery.js` — **static** is the container name. Again, you can use FFUF to enumerate container names. As you can see, the container name is **static**, a common word.

The main problem here is Azure Blob Storage does not indicate if the container name is valid or not, i.e. **static** can be a valid container name and **notnotnotvalid** invalid but we will get the same response for both:

```
<Error>
<Code>ResourceNotFound</Code>
<Message>
    The specified resource does not exist. RequestId:4f8c64bf-701e-0024-4099-3cb3d7000000 Time:2024-11-22T04:47:01.2790826Z
</Message>
</Error>
```

## Accessing blobs from a container
But Microsoft is not an evil company, and there is a way to identify if the container name is valid or not. We need to append `?restype=container&comp=list` or just `?comp=list` to the end of the URL, and blobs will be listed.

![image](/assets/attacking-azure-blob-storage/listing.png)

With this in mind, we can go back to FFUF and enumerate valid container names through this command:
```
ffuf -c -w /opt/SecLists/Discovery/Web-Content/common.txt --fc 404 --mc all -u https://000pp.blob.core.windows.net/FUZZ?comp=list
ffuf -c -w /opt/SecLists/Discovery/Web-Content/common.txt --fc 404 --mc all -u https://000pp.blob.core.windows.net/FUZZ?restype=container&comp=list
```

Of course, you can use the tool of your choice, but I really like FFUF and have been using it for the last few years.

Now you can list the blobs. You just need to access the URL indicated by the Name or Url values. For example, if I want to access the .less file from the image I used above, the URL would be something like this: `https://000pp.blob.core.windows.net/static/backend/REDACTED/css/REDACTED.less`

![image](/assets/attacking-azure-blob-storage/content.png)

I used this file as an example, but you can find internal documents by searching for files that end with `pdf`, `csv`, `xlsx`, `xls`, `docx`, or low-hanging fruits with `js`, `zip`, `sql` files. Or just adapt the search based on the environment you're exploring. If the web app is developed with PHP, you can search for `php`, `inc`, `bkp`.

Another problem is Azure Blob Storage is used to store a large scale of files. If you want to find files that end with pdf, you will need to use CTRL+F on your browser and filter one by one. If that wasn't enough, you may come across errors like `FeatureVersionMismatch` and will need to specify the `x-ms-version` header with the vlaue `2020-04-08`.

I'm a person that likes to develop tools/scripts and bring more convenience to my life. So, I developed a tool to help with Azure Blob Storage. I called it Blobber, and it is developed with Python.

## Blobber
Blobber automates the process of adding `?restype=container&comp=list` to the URL, checks for errors, tries to bypass them, and lets you view only the really important data and filter by extensions with more convenience. You can skip the filter by extensions flag too, but be careful because a lot of content will be printed (probably).

![image](/assets/attacking-azure-blob-storage/blobber1.png)

![image](/assets/attacking-azure-blob-storage/blobber2.png)

I will not release Blobber for now because I want to do more tests and not release a tool that does not work as expected. However, it will eventually be available on my GitHub. The repo will be accessible through this URL [https://github.com/000pp/blobber](https://github.com/000pp/blobber).

## Conclusion
Today we learned a bit more about the Azure Blob Storage service and how valuable it is to find one with anonymous access enabled. I really enjoyed reading about this through Microsoft's documentation and developing this script (Blobber). In my opinion, this is the best way to learn something new and improve your skills. I hope all you guys liked this post and learned something new. I hope to see you again soon.

## References
- https://learn.microsoft.com/en-us/azure/storage/blobs/
- https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blobs-overview
- https://learn.microsoft.com/en-us/rest/api/storageservices/blob-service-rest-api
- https://learn.microsoft.com/en-us/rest/api/storageservices/blob-service-concepts
- https://learn.microsoft.com/en-us/rest/api/storageservices/enumerating-blob-resources
- https://learn.microsoft.com/en-us/rest/api/storageservices/operations-on-containers