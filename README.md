# constrained-delegation-jdbc
Sample Program for testing Kerberos Constrained Delegation using JDBC driver.

## Basic Java program run commands 
compile and run (tested on Mac)
```shell
javac <path/to/ConstrainedDelegationSample.java>
cd sample/src
java -cp "<PATH-TO-DRIVER-JAR>:." com.sample.ConstrainedDelegationSample "<path/to/krb5.conf>" "runAsUserPrincipalName" "impersonatedUserName" "<path/to/runAsUser.keytab>"
```

## Output 
The program output is dependent on the query used in getQuery method. It is suggested to use a SQL query which returns the 
current user on the database or current session user to verify that the viewer delegation was successful. The output of the 
query should be equal to the viewer name (impersonatedUserName).