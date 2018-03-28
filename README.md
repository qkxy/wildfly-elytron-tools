# wildfly-elytron-tools
Some Elytron realm and converter to make it usable in real word use cases.


For installation use jboss_cli.sh eg: 

```
module add \
--name=hu.qkxy.wildfly.elytron.tools \
--resources= /path_to_file/wildfly.elytron.tools-0.0.1-SNAPSHOT.jar \
--dependencies=org.jboss.logging,org.wildfly.security.elytron,org.wildfly.extension.elytron
 ```