# Google+ Java Quickstart with maven

Prepare
-------
Copy/paste client_secrets.json.example to client_secrets.json and put your credentials

Build
-----
```
mvn clean install
```

Run
---
```
mvn exec:java -Dexec.mainClass="com.google.plus.samples.quickstart.Signin"
```
.. then browse [http://localhost:4567](http://localhost:4567)