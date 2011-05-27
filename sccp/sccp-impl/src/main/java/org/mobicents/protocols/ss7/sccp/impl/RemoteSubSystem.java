/*
 * JBoss, Home of Professional Open Source
 * Copyright 2011, Red Hat, Inc. and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.mobicents.protocols.ss7.sccp.impl;

import javolution.xml.XMLFormat;
import javolution.xml.XMLSerializable;
import javolution.xml.stream.XMLStreamException;

/**
 * 
 * @author amit bhayani
 * 
 */
public class RemoteSubSystem implements XMLSerializable {
	private static final String REMOTE_SPC = "remoteSpc";
	private static final String REMOTE_SSN = "remoteSsn";
	private static final String REMOTE_SSN_FLAG = "remoteSsnFlag";

	private int remoteSpc;
	private int remoteSsn;
	private int remoteSsnFlag;

	private boolean remoteSsnProhibited;

	public RemoteSubSystem(int remoteSpc, int remoteSsn, int remoteSsnFlag) {
		this.remoteSpc = remoteSpc;
		this.remoteSsn = remoteSsn;
		this.remoteSsnFlag = remoteSsnFlag;
	}

	public boolean isRemoteSsnProhibited() {
		return remoteSsnProhibited;
	}

	public void setRemoteSsnProhibited(boolean remoteSsnProhibited) {
		this.remoteSsnProhibited = remoteSsnProhibited;
	}

	public int getRemoteSpc() {
		return remoteSpc;
	}

	public int getRemoteSsn() {
		return remoteSsn;
	}

	public int getRemoteSsnFlag() {
		return remoteSsnFlag;
	}

	
	public String toString() {
		return "RemoteSubSystem [remoteSpc=" + remoteSpc + ", remoteSsn=" + remoteSsn + ", remoteSsnFlag=" + remoteSsnFlag + ", remoteSsnProhibited="
				+ remoteSsnProhibited + "]";
	}

	
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + remoteSpc;
		result = prime * result + remoteSsn;
		return result;
	}

	
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		RemoteSubSystem other = (RemoteSubSystem) obj;
		if (remoteSpc != other.remoteSpc)
			return false;
		if (remoteSsn != other.remoteSsn)
			return false;
		return true;
	}

	protected static final XMLFormat<RemoteSubSystem> XML = new XMLFormat<RemoteSubSystem>(RemoteSubSystem.class) {

		public void write(RemoteSubSystem ai, OutputElement xml) throws XMLStreamException {
			xml.setAttribute(REMOTE_SPC, ai.remoteSpc);
			xml.setAttribute(REMOTE_SSN, ai.remoteSsn);
			xml.setAttribute(REMOTE_SSN_FLAG, ai.remoteSsnFlag);

		}

		public void read(InputElement xml, RemoteSubSystem ai) throws XMLStreamException {
			ai.remoteSpc = xml.getAttribute(REMOTE_SPC).toInt();
			ai.remoteSsn = xml.getAttribute(REMOTE_SSN).toInt();
			ai.remoteSsnFlag = xml.getAttribute(REMOTE_SSN_FLAG).toInt();
		}
	};
}