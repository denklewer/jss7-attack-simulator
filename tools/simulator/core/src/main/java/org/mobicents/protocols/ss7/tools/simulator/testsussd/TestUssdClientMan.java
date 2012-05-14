/*
 * TeleStax, Open Source Cloud Communications  Copyright 2012.
 * and individual contributors
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

package org.mobicents.protocols.ss7.tools.simulator.testsussd;

import javolution.xml.XMLFormat;
import javolution.xml.stream.XMLStreamException;
import org.mobicents.protocols.ss7.map.api.MAPApplicationContext;
import org.mobicents.protocols.ss7.map.api.MAPApplicationContextName;
import org.mobicents.protocols.ss7.map.api.MAPApplicationContextVersion;
import org.mobicents.protocols.ss7.map.api.MAPDialog;
import org.mobicents.protocols.ss7.map.api.MAPDialogListener;
import org.mobicents.protocols.ss7.map.api.MAPException;
import org.mobicents.protocols.ss7.map.api.MAPMessage;
import org.mobicents.protocols.ss7.map.api.MAPProvider;
import org.mobicents.protocols.ss7.map.api.dialog.MAPAbortProviderReason;
import org.mobicents.protocols.ss7.map.api.dialog.MAPAbortSource;
import org.mobicents.protocols.ss7.map.api.dialog.MAPNoticeProblemDiagnostic;
import org.mobicents.protocols.ss7.map.api.dialog.MAPProviderError;
import org.mobicents.protocols.ss7.map.api.dialog.MAPRefuseReason;
import org.mobicents.protocols.ss7.map.api.dialog.MAPUserAbortChoice;
import org.mobicents.protocols.ss7.map.api.errors.MAPErrorMessage;
import org.mobicents.protocols.ss7.map.api.primitives.AddressNature;
import org.mobicents.protocols.ss7.map.api.primitives.AddressString;
import org.mobicents.protocols.ss7.map.api.primitives.AlertingPattern;
import org.mobicents.protocols.ss7.map.api.primitives.IMSI;
import org.mobicents.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.mobicents.protocols.ss7.map.api.primitives.NumberingPlan;
import org.mobicents.protocols.ss7.map.api.primitives.USSDString;
import org.mobicents.protocols.ss7.map.api.service.supplementary.MAPDialogSupplementary;
import org.mobicents.protocols.ss7.map.api.service.supplementary.MAPServiceSupplementaryListener;
import org.mobicents.protocols.ss7.map.api.service.supplementary.ProcessUnstructuredSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.ProcessUnstructuredSSResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.UnstructuredSSNotifyRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.UnstructuredSSNotifyResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.UnstructuredSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.UnstructuredSSResponse;
import org.mobicents.protocols.ss7.map.dialog.MAPUserAbortChoiceImpl;
import org.mobicents.protocols.ss7.map.primitives.AlertingPatternImpl;
import org.mobicents.protocols.ss7.tcap.asn.ApplicationContextName;
import org.mobicents.protocols.ss7.tcap.asn.comp.Problem;
import org.mobicents.protocols.ss7.tools.simulator.Stoppable;
import org.mobicents.protocols.ss7.tools.simulator.common.AddressNatureType;
import org.mobicents.protocols.ss7.tools.simulator.common.NumberingPlanType;
import org.mobicents.protocols.ss7.tools.simulator.level3.MapMan;
import org.mobicents.protocols.ss7.tools.simulator.management.TesterHost;

/**
 * 
 * @author sergey vetyutnev
 * 
 */
public class TestUssdClientMan implements TestUssdClientManMBean, Stoppable, MAPDialogListener, MAPServiceSupplementaryListener {

	public static String SOURCE_NAME = "TestUssdClient";

	private static final String MSISDN_ADDRESS = "msisdnAddress";
	private static final String MSISDN_ADDRESS_NATURE = "msisdnAddressNature";
	private static final String MSISDN_NUMBERING_PLAN = "msisdnNumberingPlan";
	private static final String DATA_CODING_SCHEME = "dataCodingScheme";
	private static final String ALERTING_PATTERN = "alertingPattern";

	private String msisdnAddress = "";
	private AddressNature msisdnAddressNature = AddressNature.international_number;
	private NumberingPlan msisdnNumberingPlan = NumberingPlan.ISDN;
	private int dataCodingScheme = 0x0F;
	private int alertingPattern = -1;

	private final String name;
	private TesterHost testerHost;
	private MapMan mapMan;

	private int countProcUnstReq = 0;
	private int countProcUnstResp = 0;
	private int countUnstReq = 0;
	private int countUnstResp = 0;
	private int countUnstNotifReq = 0;
	private MAPDialogSupplementary currentDialog = null;
	private Long invokeId = null;
	private boolean isStarted = false;
	private String currentRequestDef = "";


	public TestUssdClientMan() {
		this.name = "???";
	}

	public TestUssdClientMan(String name) {
		this.name = name;
	}

	public void setTesterHost(TesterHost testerHost) {
		this.testerHost = testerHost;
	}

	public void setMapMan(MapMan val) {
		this.mapMan = val;
	}	


	@Override
	public String getMsisdnAddress() {
		return msisdnAddress;
	}

	@Override
	public void setMsisdnAddress(String val) {
		msisdnAddress = val;
		this.testerHost.markStore();
	}

	@Override
	public AddressNatureType getMsisdnAddressNature() {
		return new AddressNatureType(msisdnAddressNature.getIndicator());
	}

	@Override
	public String getMsisdnAddressNature_Value() {
		return msisdnAddressNature.toString();
	}

	@Override
	public void setMsisdnAddressNature(AddressNatureType val) {
		msisdnAddressNature = AddressNature.getInstance(val.intValue());
		this.testerHost.markStore();
	}

	@Override
	public NumberingPlanType getMsisdnNumberingPlan() {
		return new NumberingPlanType(msisdnNumberingPlan.getIndicator());
	}

	@Override
	public String getMsisdnNumberingPlan_Value() {
		return msisdnNumberingPlan.toString();
	}

	@Override
	public void setMsisdnNumberingPlan(NumberingPlanType val) {
		msisdnNumberingPlan = NumberingPlan.getInstance(val.intValue());
		this.testerHost.markStore();
	}

	@Override
	public int getDataCodingScheme() {
		return dataCodingScheme;
	}

	@Override
	public void setDataCodingScheme(int val) {
		dataCodingScheme = val;
		this.testerHost.markStore();
	}

	@Override
	public int getAlertingPattern() {
		return alertingPattern;
	}

	@Override
	public void setAlertingPattern(int val) {
		alertingPattern = val;
		this.testerHost.markStore();
	}

	@Override
	public void putMsisdnAddressNature(String val) {
		AddressNatureType x = AddressNatureType.createInstance(val);
		if (x != null)
			this.setMsisdnAddressNature(x);
	}

	@Override
	public void putMsisdnNumberingPlan(String val) {
		NumberingPlanType x = NumberingPlanType.createInstance(val);
		if (x != null)
			this.setMsisdnNumberingPlan(x);
	}

	@Override
	public String getCurrentRequestDef() {
		if (this.currentDialog != null)
			return "CurDialog: " + currentRequestDef;
		else
			return "PrevDialog: " + currentRequestDef;
	}


	@Override
	public String getState() {
		StringBuilder sb = new StringBuilder();
		sb.append("<html>");
		sb.append(SOURCE_NAME);
		sb.append(": CurDialog=");
		MAPDialogSupplementary curDialog = currentDialog;
		if (curDialog != null)
			sb.append(curDialog.getDialogId());
		else
			sb.append("No");
		sb.append("<br>Count: processUnstructuredSSRequest-");
		sb.append(countProcUnstReq);
		sb.append(", processUnstructuredSSResponse-");
		sb.append(countProcUnstResp);
		sb.append("<br>unstructuredSSRequest-");
		sb.append(countUnstReq);
		sb.append(", unstructuredSSResponse-");
		sb.append(countUnstResp);
		sb.append(", unstructuredSSNotify-");
		sb.append(countUnstNotifReq);
		sb.append("</html>");
		return sb.toString();
	}

	public boolean start() {
		MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
		mapProvider.getMAPServiceSupplementary().acivate();
		mapProvider.getMAPServiceSupplementary().addMAPServiceListener(this);
		mapProvider.addMAPDialogListener(this);
		this.testerHost.sendNotif(SOURCE_NAME, "USSD Client has been started", "", true);
		isStarted = true;
		
		return true;
	}

	@Override
	public void stop() {
		MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
		isStarted = false;
		this.doRemoveDialog();
		mapProvider.getMAPServiceSupplementary().deactivate();
		mapProvider.getMAPServiceSupplementary().removeMAPServiceListener(this);
		mapProvider.removeMAPDialogListener(this);
		this.testerHost.sendNotif(SOURCE_NAME, "USSD Client has been stopped", "", true);
	}

	@Override
	public void execute() {
	}

	@Override
	public String closeCurrentDialog() {
		if (isStarted) {
			MAPDialogSupplementary curDialog = currentDialog;
			if (curDialog != null) {
				try {
					MAPUserAbortChoice choice = new MAPUserAbortChoiceImpl();
					choice.setUserSpecificReason();
					curDialog.abort(choice);
					this.doRemoveDialog();
					return "The current dialog has been closed";
				} catch (MAPException e) {
					this.doRemoveDialog();
					return "Exception when closing the current dialog: " + e.toString();
				}
			} else {
				return "No current dialog";
			}
		} else {
			return "The tester is not started";
		}
	}

	private void doRemoveDialog() {
		currentDialog = null;
		currentRequestDef = "";
	}

	@Override
	public String performProcessUnstructuredRequest(String msg) {
		if (!isStarted)
			return "The tester is not started";
		MAPDialogSupplementary curDialog = currentDialog;
		if (curDialog != null)
			return "The current dialog exists. Finish it previousely";
		
		MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
		if (msg == null || msg.equals(""))
			return "USSD message is empty";
		USSDString ussdString = mapProvider.getMAPParameterFactory().createUSSDString(msg);
		MAPApplicationContext mapUssdAppContext = MAPApplicationContext.getInstance(MAPApplicationContextName.networkUnstructuredSsContext,
				MAPApplicationContextVersion.version2);

		try {
			currentDialog = mapProvider.getMAPServiceSupplementary().createNewDialog(mapUssdAppContext, this.mapMan.createOrigAddress(),
					this.mapMan.createOrigReference(), this.mapMan.createDestAddress(), this.mapMan.createDestReference());
			curDialog = currentDialog;
			invokeId = null;

			ISDNAddressString msisdn = null;
			if (this.msisdnAddress != null && !this.msisdnAddress.equals("")) {
				msisdn = mapProvider.getMAPParameterFactory().createISDNAddressString(this.msisdnAddressNature, this.msisdnNumberingPlan, this.msisdnAddress);
			}

			AlertingPattern alPattern = null;
			if (this.alertingPattern >= 0 && this.alertingPattern <= 255)
				alPattern = new AlertingPatternImpl(new byte[] { (byte) this.alertingPattern });
			curDialog.addProcessUnstructuredSSRequest((byte) this.dataCodingScheme, ussdString, alPattern, msisdn);

			curDialog.send();

			currentRequestDef += "Sent procUnstrSsReq=\"" + msg + "\";";
			this.countProcUnstReq++;
			String uData = this.createUssdMessageData(curDialog.getDialogId(), this.dataCodingScheme, msisdn, alPattern);
			this.testerHost.sendNotif(SOURCE_NAME, "Sent: procUnstrSsReq: " + msg, uData, true);
			
			return "ProcessUnstructuredSSRequest has been sent";
		} catch (MAPException ex) {
			return "Exception when sending ProcessUnstructuredSSRequest: " + ex.toString();
		}		

//		// here we make map call to peer :)
//		MAPProvider mapProvider = this.mapStack.getMAPProvider();
//		// here, if no dialog exists its initial call :)
//		String punchedText = this._field_punch_display.getText();
//		if (punchedText == null || punchedText.equals("")) {
//			return;
//		}
//		USSDString ussdString = mapProvider.getMAPParameterFactory().createUSSDString(punchedText);
//		if (this.clientDialog == null) {
//			try {
//				this.clientDialog = mapProvider.getMAPServiceSupplementary().createNewDialog(mapUssdAppContext, peer1Address, orgiReference, peer2Address,
//						destReference);
//			} catch (MAPException ex) {
//				Logger.getLogger(UssdsimulatorView.class.getName()).log(Level.SEVERE, null, ex);
//				this._field_punch_display.setText("Failed to create MAP dialog: " + ex);
//				this.onlyKeyPadContent = false;
//				return;
//			}
//
//			try {
//				ISDNAddressString msisdn = this.mapStack.getMAPProvider().getMAPParameterFactory()
//						.createISDNAddressString(AddressNature.international_number, NumberingPlan.ISDN, "31628838002");
//
//				clientDialog.addProcessUnstructuredSSRequest((byte) 0x0F, ussdString,null, msisdn);
//
//				clientDialog.send();
//				this._field_punch_display.setText("");
//				this._keypad_button_break.setEnabled(true);
//				this._field_result_display.append("\n");
//				this._field_result_display.append(punchedText);
//			} catch (MAPException ex) {
//				Logger.getLogger(UssdsimulatorView.class.getName()).log(Level.SEVERE, null, ex);
//				this._field_punch_display.setText("Failed to pass USSD request: " + ex);
//				this.onlyKeyPadContent = false;
//				return;
//			}
//		} else {
//			// This is response to Unstructured Request from GW
//
//			try {
//				ISDNAddressString msisdn = this.mapStack.getMAPProvider().getMAPParameterFactory()
//				.createISDNAddressString(AddressNature.international_number, NumberingPlan.ISDN, "31628838002");
//				// clientDialog.addProcessUnstructuredSSRequest((byte) 0x0F,
//				// ussdString, msisdn);
//				clientDialog.addUnstructuredSSResponse(this.ussdInditaion.getInvokeId(),  (byte) 0x0F, ussdString);
//
//				clientDialog.send();
//				this._field_punch_display.setText("");
//				this._keypad_button_break.setEnabled(true);
//				this._field_result_display.append("\n");
//				this._field_result_display.append(punchedText);
//			} catch (MAPException ex) {
//				Logger.getLogger(UssdsimulatorView.class.getName()).log(Level.SEVERE, null, ex);
//				this._field_punch_display.setText("Failed to pass USSD request: " + ex);
//				this.onlyKeyPadContent = false;
//				return;
//			}
//		}
		
	}

	private String createUssdMessageData(long dialogId, int dataCodingScheme, ISDNAddressString msisdn, AlertingPattern alPattern) {
		StringBuilder sb = new StringBuilder();
		sb.append("dialogId=");
		sb.append(dialogId);
		sb.append(" DataCodingSchema=");
		sb.append(dataCodingScheme);
		sb.append(" ");
		if (msisdn != null) {
			sb.append(msisdn.toString());
			sb.append(" ");
		}
		if (alPattern != null) {
			sb.append(alPattern.toString());
			sb.append(" ");
		}
		return sb.toString();
	}

	protected static final XMLFormat<TestUssdClientMan> XML = new XMLFormat<TestUssdClientMan>(TestUssdClientMan.class) {

		public void write(TestUssdClientMan clt, OutputElement xml) throws XMLStreamException {
			xml.setAttribute(DATA_CODING_SCHEME, clt.dataCodingScheme);
			xml.setAttribute(ALERTING_PATTERN, clt.alertingPattern);

			xml.add(clt.msisdnAddress, MSISDN_ADDRESS);
			xml.add(clt.msisdnAddressNature.toString(), MSISDN_ADDRESS_NATURE);
			xml.add(clt.msisdnNumberingPlan.toString(), MSISDN_NUMBERING_PLAN);
		}

		public void read(InputElement xml, TestUssdClientMan clt) throws XMLStreamException {
			clt.dataCodingScheme = xml.getAttribute(DATA_CODING_SCHEME).toInt();
			clt.alertingPattern = xml.getAttribute(ALERTING_PATTERN).toInt();

			clt.msisdnAddress = (String) xml.get(MSISDN_ADDRESS, String.class);
			String an = (String) xml.get(MSISDN_ADDRESS_NATURE, String.class);
			clt.msisdnAddressNature = AddressNature.valueOf(an);
			String np = (String) xml.get(MSISDN_NUMBERING_PLAN, String.class);
			clt.msisdnNumberingPlan = NumberingPlan.valueOf(np);
		}
	};

	@Override
	public String performUnstructuredResponse(String msg) {
		if (!isStarted)
			return "The tester is not started";
		MAPDialogSupplementary curDialog = currentDialog;
		if (curDialog == null)
			return "No current dialog exists. Start it previousely";
		if (invokeId == null)
			return "No pending unstructured request";

		MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
		if (msg == null || msg.equals(""))
			return "USSD message is empty";
		USSDString ussdString = mapProvider.getMAPParameterFactory().createUSSDString(msg);

		try {
			curDialog.addUnstructuredSSResponse(invokeId, (byte) this.dataCodingScheme, ussdString);

			curDialog.send();

			invokeId = null;

			currentRequestDef += "Sent unstrSsResp=\"" + msg + "\";";
			this.countUnstResp++;
			String uData = this.createUssdMessageData(curDialog.getDialogId(), this.dataCodingScheme, null, null);
			this.testerHost.sendNotif(SOURCE_NAME, "Sent: unstrSsResp: " + msg, uData, true);
			
			return "ProcessUnstructuredSSRequest has been sent";
		} catch (MAPException ex) {
			return "Exception when sending UnstructuredSSResponse: " + ex.toString();
		}		
	}


	@Override
	public void onErrorComponent(MAPDialog mapDialog, Long invokeId, MAPErrorMessage mapErrorMessage) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onProviderErrorComponent(MAPDialog mapDialog, Long invokeId, MAPProviderError providerError) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onRejectComponent(MAPDialog mapDialog, Long invokeId, Problem problem) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onInvokeTimeout(MAPDialog mapDialog, Long invokeId) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onMAPMessage(MAPMessage mapMessage) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onProcessUnstructuredSSRequest(ProcessUnstructuredSSRequest procUnstrReqInd) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onProcessUnstructuredSSResponse(ProcessUnstructuredSSResponse ind) {
		if (!isStarted)
			return;
		MAPDialogSupplementary curDialog = currentDialog;
		if (curDialog != ind.getMAPDialog())
			return;

		currentRequestDef += "procUnstrSsResp=\"" + ind.getUSSDString().getString() + "\";";
		this.countProcUnstResp++;
		String uData = this.createUssdMessageData(curDialog.getDialogId(), ind.getUSSDDataCodingScheme(), null, null);
		this.testerHost.sendNotif(SOURCE_NAME, "Rsvd: procUnstrSsResp: " + ind.getUSSDString().getString(), uData, true);
		
		this.doRemoveDialog();
	}

	@Override
	public void onUnstructuredSSRequest(UnstructuredSSRequest ind) {
		if (!isStarted)
			return;
		MAPDialogSupplementary curDialog = currentDialog;
		if (curDialog != ind.getMAPDialog())
			return;

		invokeId = ind.getInvokeId();
		
		currentRequestDef += "Rsvd: unstrSsReq=\"" + ind.getUSSDString().getString() + "\";";
		this.countUnstReq++;
		String uData = this.createUssdMessageData(curDialog.getDialogId(), ind.getUSSDDataCodingScheme(), null, null);
		this.testerHost.sendNotif(SOURCE_NAME, "Rsvd: unstrSsReq: " + ind.getUSSDString().getString(), uData, true);
	}

	@Override
	public void onUnstructuredSSResponse(UnstructuredSSResponse unstrResInd) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onUnstructuredSSNotifyRequest(UnstructuredSSNotifyRequest ind) {
		if (!isStarted)
			return;

		MAPDialogSupplementary dlg = ind.getMAPDialog();
		invokeId = ind.getInvokeId();
		
		this.countUnstNotifReq++;
		String uData = this.createUssdMessageData(dlg.getDialogId(), ind.getUSSDDataCodingScheme(), null, null);
		this.testerHost.sendNotif(SOURCE_NAME, "Rsvd: unstrSsNotify: " + ind.getUSSDString().getString(), uData, true);

		try {
			dlg.addUnstructuredSSNotifyResponse(invokeId);
		} catch (MAPException e) {
			this.testerHost.sendNotif(SOURCE_NAME, "Exception when invoking addUnstructuredSSNotifyResponse() : " + e.getMessage(), e, true);
		}
		// ...........................
	}

	@Override
	public void onUnstructuredSSNotifyResponse(UnstructuredSSNotifyResponse unstrNotifyInd) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDialogDelimiter(MAPDialog mapDialog) {
	}

	@Override
	public void onDialogRequest(MAPDialog mapDialog, AddressString destReference, AddressString origReference, MAPExtensionContainer extensionContainer) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDialogRequestEricsson(MAPDialog mapDialog, AddressString destReference, AddressString origReference, IMSI eriImsi, AddressString eriVlrNo) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDialogAccept(MAPDialog mapDialog, MAPExtensionContainer extensionContainer) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDialogReject(MAPDialog mapDialog, MAPRefuseReason refuseReason, MAPProviderError providerError,
			ApplicationContextName alternativeApplicationContext, MAPExtensionContainer extensionContainer) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDialogUserAbort(MAPDialog mapDialog, MAPUserAbortChoice userReason, MAPExtensionContainer extensionContainer) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDialogProviderAbort(MAPDialog mapDialog, MAPAbortProviderReason abortProviderReason, MAPAbortSource abortSource,
			MAPExtensionContainer extensionContainer) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDialogClose(MAPDialog mapDialog) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDialogNotice(MAPDialog mapDialog, MAPNoticeProblemDiagnostic noticeProblemDiagnostic) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDialogRelease(MAPDialog mapDialog) {
		if (this.currentDialog == mapDialog)
			this.doRemoveDialog();
	}

	@Override
	public void onDialogTimeout(MAPDialog mapDialog) {
		// TODO Auto-generated method stub
		
	}
}

