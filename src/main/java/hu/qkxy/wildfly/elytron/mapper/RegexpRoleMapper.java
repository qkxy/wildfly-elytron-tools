package hu.qkxy.wildfly.elytron.mapper;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.jboss.logging.Logger;

import org.wildfly.extension.elytron.Configurable;
import org.wildfly.security.authz.RoleMapper;
import org.wildfly.security.authz.Roles;

/**
 * Maps matched roles to destination role and optionally remove matched roles.
 * Configuration given by properties eg.:
 * <pre>
 * {@code
 * <custom-role-mapper
 *   name="MyRoleMapper"
 *   module="hu.qkxy.wildfly.elytron.tools"
 *   class-name="hu.qkxy.wildfly.elytron.mapper.RegexpRoleMapper"
 * >
 *    <configuration>
 *        <property name="rule1.regexp" value="SOME_REALM_ROLE_NAME.*" />
 *        <property name="rule1.destRole" value="some-application-role-name" />
 *        <property name="rule1.doReplace" value="true" />
 *    </configuration>
 * </custom-role-mapper>
 * }
 * </pre>
 * Property name start with the rule name and followed by a dot and than the attribute name:
 * <ul>
 * <li>regexp: mandatory, the regular expression to match to the role name.
 * <li>destRole: mandatory, role added to the roles set when regexp matches.
 * <li>doReplace: optional, if true then matched roles will be removed from the roles set. Default value is false.
 * </ul>
 * 
 * All rules matched over all the source rules and rule set modification will take place after matching.
 * 
 * @author <a href="mailto:zoltan.kukk@gmail.com">Zoltan Kukk</a>
 *
 */
public class RegexpRoleMapper implements RoleMapper,Configurable{
	private static final Logger LOG = Logger.getLogger(RegexpRoleMapper.class);
	
	private static final String PARAM_REGEXP = "regexp";
	private static final String PARAM_DEST_ROLE = "destRole";
	private static final String PARAM_DO_REPLACE = "doReplace";
	private static final String PARAM_TRUE_VALUE = "true";
	private static final String PARAM_SEPARATOR_REGEXP = "\\.";
	
	private Map<String, TransformRule> rules; 
	
	public RegexpRoleMapper() {
		rules = new HashMap<>();
	}

	@Override
	public void initialize(Map<String, String> conf) {
		conf.keySet().forEach(
				name->{
					String[] parts = name.split(PARAM_SEPARATOR_REGEXP);
					if (parts.length==2) {
						String ruleName = parts[0];
						String paramName = parts[1];
						TransformRule rule;
						if (rules.containsKey(ruleName)) {
							rule = rules.get(ruleName);
						}
						else {
							rule = new TransformRule();
							rules.put(ruleName, rule);
						}
						
						if(paramName.equalsIgnoreCase(PARAM_REGEXP)) {
							rule.setRegexp(conf.get(name));
						}
						else if(paramName.equalsIgnoreCase(PARAM_DEST_ROLE)) {
							rule.setDestRole(conf.get(name));
						}
						else if(paramName.equalsIgnoreCase(PARAM_DO_REPLACE)) {
							rule.setDoReplace(conf.get(name).equalsIgnoreCase(PARAM_TRUE_VALUE));
						}
					}
				}
				);
		if (LOG.isTraceEnabled()) {
			StringBuilder sb = new StringBuilder();
			rules.keySet()
				 .forEach(
					name->sb.append(name)
							.append(":")
							.append("\"").append(rules.get(name).getRegexp()).append("\"")
							.append("==>")
							.append("\"").append(rules.get(name).getDestRole()).append("\"")
							.append(rules.get(name).isDoReplace()?"replace":"add")
							.append("\n")
			      );
			LOG.trace("Config initialized:\n" + sb.toString());
		}
	}

	@Override
	public Roles mapRoles(Roles rolesToMap) {
		if (rolesToMap == null || rolesToMap.isEmpty() || rules.isEmpty()) {
			if (LOG.isTraceEnabled()) {
				LOG.trace("There is no source roles, do nothing.");
			}
			return rolesToMap;
		}
		
		Set<String> roles = new HashSet<>();
		rolesToMap.forEach(r->roles.add(r));
		
		Set<String> rolesToAdd = new HashSet<>();
		Set	<String> rolesToRemove = new HashSet<>();

		rules.keySet()
			 .stream()
			 .sorted()
			 .forEach(name->{
				 TransformRule rule = rules.get(name);
				 if (rule.getRegexp()!=null && rule.getDestRole()!=null) {
					 Pattern p = Pattern.compile(rule.getRegexp());
					 roles.forEach(role->{
						 if (p.matcher(role).matches()) {
							 rolesToAdd.add(rule.destRole);
							 if (rule.isDoReplace()) {
								 rolesToRemove.add(role);
							 }
						 }
					 }
				    );
				 }
			 });

		roles.removeAll(rolesToRemove);
		roles.addAll(rolesToAdd);

		if (LOG.isTraceEnabled()) {
			StringBuilder sourceRoles = new StringBuilder();
			rolesToMap.forEach(role->sourceRoles.append(role).append(","));
			if (sourceRoles.length()>0) {
				sourceRoles.setLength(sourceRoles.length()-1);
			}
			
			StringBuilder destRoles = new StringBuilder();
			roles.forEach(role->destRoles.append(role).append(","));
			if (destRoles.length()>0) {
				destRoles.setLength(destRoles.length()-1);
			}
			
			LOG.trace("Mapping result is: [" + sourceRoles.toString() + "]==>[" + destRoles.toString() + "]");
		}

		return Roles.fromSet(roles);
	}

	private static class TransformRule{
		private String regexp;
		private String destRole;
		private boolean doReplace = true;
		
		public boolean isDoReplace() {
			return doReplace;
		}

		public void setDoReplace(boolean doReplace) {
			this.doReplace = doReplace;
		}

		public TransformRule() {
			this(null, null);
		}
		
		public TransformRule(String regexp, String destRole) {
			this.regexp = regexp;
			this.destRole = destRole;
		}
		
		public String getRegexp() {
			return regexp;
		}
		public void setRegexp(String regexp) {
			this.regexp = regexp;
		}
		public String getDestRole() {
			return destRole;
		}
		public void setDestRole(String destRole) {
			this.destRole = destRole;
		}
		
	}
}
