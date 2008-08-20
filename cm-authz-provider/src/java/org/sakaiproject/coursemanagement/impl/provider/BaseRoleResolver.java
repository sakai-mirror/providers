package org.sakaiproject.coursemanagement.impl.provider;

import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public abstract class BaseRoleResolver implements RoleResolver {
	static final Log log = LogFactory.getLog(BaseRoleResolver.class);

	/** Map of CM section roles to Sakai roles */
	protected Map<String, String> roleMap;

	public BaseRoleResolver() {
		super();
	}

	public String convertRole(String cmRole) {
		if (cmRole == null) {
			log.warn("Can not convert CM role 'null' to a sakai role.");
			return null;
		}
		String sakaiRole = (String)roleMap.get(cmRole);
		if(sakaiRole== null) {
			log.warn("Unable to find sakai role for CM role " + cmRole);
			return null;
		} else {
			return sakaiRole;
		}
	}

	public void setRoleMap(Map<String, String> roleMap) {
		this.roleMap = roleMap;
	}

}