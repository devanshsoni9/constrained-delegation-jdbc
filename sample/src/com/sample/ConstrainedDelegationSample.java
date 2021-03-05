package com.sample;

import com.sun.security.auth.module.Krb5LoginModule;
import com.sun.security.jgss.ExtendedGSSCredential;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class ConstrainedDelegationSample {

    private String              impersonatedUser;
    private String              runAsUser;
    private Subject             serviceSubject;
    private static Oid          krb5Oid;
    private GSSCredential       impersonationCredentials;
    private static final String CONNECTION_URI = "jdbc:blahBlah";

    static {
        try {
            krb5Oid = new Oid("1.2.840.113554.1.2.2");
        } catch (GSSException e) {
            System.out.println("Error creating Oid: " + e);
            System.exit(-1);
        }
    }

    ConstrainedDelegationSample(String runAsUser, String impersonatedUser, String keytabPath) throws Exception{
        this.runAsUser = runAsUser;
        this.impersonatedUser = impersonatedUser;
        this.serviceSubject = doInitialLogin(keytabPath);
        try {
            this.impersonationCredentials = kerberosImpersonate();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private void connect(){

        if (impersonationCredentials != null) {
            try {
                // Create a connection for target service thanks S4U2proxy mechanism
                Connection con = createConnection();

                ResultSet result = con.createStatement().executeQuery(getQuery());
                while (result.next()) {
                    System.out.println(" User on DB: " + result.getString(1)); // .getString("SYSTEM_USER"));
                }
            } catch (Exception ex) {

                System.out.println(" Exception caught in createConnection ");
                ex.printStackTrace();
            }
        }
    }

    /**
     *
     * @param args -
     *             1.path of krb5.conf
     *             2.runAsUser
     *             3.Impersonation User/Viewer
     *             4.keytab path of runAsUser
     * @throws Exception
     */
    public static void main(String[] args) throws Exception{
       Arrays.stream(args).forEach(System.out::println);
        System.setProperty("java.security.krb5.conf", args[0]);
        System.setProperty("sun.security.krb5.debug", "true");

        ConstrainedDelegationSample sample = new ConstrainedDelegationSample(args[1], args[2], args[3]);
        sample.connect();
    }

    private Subject doInitialLogin(String keytabPath) throws Exception{
        Subject serviceSubject = new Subject();

        LoginModule krb5Module = null;
        try {
            krb5Module = new Krb5LoginModule();
        } catch (Exception e) {
            System.out.print("Error loading Krb5LoginModule module: " + e);
            throw e;
        }

        System.setProperty("sun.security.krb5.debug", String.valueOf(false));

        Map<String, String> options = new HashMap<>();
        options.put("principal", runAsUser);
        options.put("useKeyTab", "true");
        options.put("doNotPrompt", "true");
        options.put("keyTab", keytabPath);
        options.put("isInitiator", "true");
        options.put("refreshKrb5Config", "true");

        System.out.println("Retrieving TGT for runAsUser using keytab");

        krb5Module.initialize(serviceSubject, null, null, options);
        try {
            krb5Module.login();
            krb5Module.commit();
        } catch (LoginException e) {
            System.out.println("Error authenticating with Kerberos: " + e);
            try {
                krb5Module.abort();
            } catch (LoginException e1) {
                System.out.println("Error aborting Kerberos authentication:  " + e1);
            }
            throw e;
        }

        return serviceSubject;
    }
    /**
     * Generate the impersonated user credentials using S4U2self mechanism
     *
     * @return the client impersonated GSSCredential
     * @throws PrivilegedActionException
     *             in case of failure
     */
    private GSSCredential kerberosImpersonate() throws PrivilegedActionException {
        return Subject.doAs(this.serviceSubject, (PrivilegedExceptionAction<GSSCredential>) () -> {
            GSSManager manager = GSSManager.getInstance();
            GSSName selfName = manager.createName(this.runAsUser, GSSName.NT_USER_NAME);

            GSSCredential selfCreds = manager.createCredential(selfName, GSSCredential.INDEFINITE_LIFETIME, krb5Oid,
                    GSSCredential.INITIATE_ONLY);
            GSSName dbUser = manager.createName(this.impersonatedUser, GSSName.NT_USER_NAME);

            return ((ExtendedGSSCredential) selfCreds).impersonate(dbUser);
        });
    }


    private Connection createConnection()
            throws PrivilegedActionException {

        this.serviceSubject.getPrivateCredentials().add(this.impersonationCredentials);

        return Subject.doAs(this.serviceSubject, (PrivilegedExceptionAction<Connection>) () -> {

            Properties driverProperties = new Properties();
            // These are driver specific properties for enabling Kerberos GSSAPI login - the ones here are valid for Postgres
            driverProperties.put("gsslib", "gssapi");
            driverProperties.put("user", this.impersonatedUser);
            return DriverManager.getConnection(CONNECTION_URI, driverProperties);
        });
    }

    protected String getQuery() {
        // this query is valid in Postgres
        return "SELECT current_user;";
    }

}