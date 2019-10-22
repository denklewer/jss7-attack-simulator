package org.mobicents.protocols.ss7.tools.simulator.tests.attack;

import org.apache.log4j.Level;
import org.apache.log4j.net.SyslogAppender;
import org.mobicents.protocols.ss7.isup.*;
import org.mobicents.protocols.ss7.isup.impl.message.ISUPMessageImpl;
import org.mobicents.protocols.ss7.isup.impl.message.InitialAddressMessageImpl;
import org.mobicents.protocols.ss7.isup.impl.message.parameter.CalledPartyNumberImpl;
import org.mobicents.protocols.ss7.isup.message.ISUPMessage;
import org.mobicents.protocols.ss7.isup.message.InitialAddressMessage;
import org.mobicents.protocols.ss7.isup.message.parameter.*;
import org.mobicents.protocols.ss7.isup.message.parameter.Number;
import org.mobicents.protocols.ss7.map.api.*;
import org.mobicents.protocols.ss7.map.api.datacoding.NationalLanguageIdentifier;
import org.mobicents.protocols.ss7.map.api.errors.AbsentSubscriberDiagnosticSM;
import org.mobicents.protocols.ss7.map.api.errors.CallBarringCause;
import org.mobicents.protocols.ss7.map.api.errors.MAPErrorMessage;
import org.mobicents.protocols.ss7.map.api.errors.SMEnumeratedDeliveryFailureCause;
import org.mobicents.protocols.ss7.map.api.primitives.*;
import org.mobicents.protocols.ss7.map.api.service.callhandling.*;
import org.mobicents.protocols.ss7.map.api.service.lsm.MAPServiceLsmListener;
import org.mobicents.protocols.ss7.map.api.service.mobility.MAPDialogMobility;
import org.mobicents.protocols.ss7.map.api.service.mobility.MAPServiceMobilityListener;
import org.mobicents.protocols.ss7.map.api.service.mobility.authentication.AuthenticationFailureReportRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.authentication.AuthenticationFailureReportResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.authentication.SendAuthenticationInfoRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.authentication.SendAuthenticationInfoResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.faultRecovery.ForwardCheckSSIndicationRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.faultRecovery.ResetRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.faultRecovery.RestoreDataRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.faultRecovery.RestoreDataResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.imei.CheckImeiRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.imei.CheckImeiResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.imei.EquipmentStatus;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.*;
import org.mobicents.protocols.ss7.map.api.service.mobility.oam.ActivateTraceModeRequest_Mobility;
import org.mobicents.protocols.ss7.map.api.service.mobility.oam.ActivateTraceModeResponse_Mobility;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.*;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberManagement.*;
import org.mobicents.protocols.ss7.map.api.service.oam.*;
import org.mobicents.protocols.ss7.map.api.service.pdpContextActivation.MAPDialogPdpContextActivation;
import org.mobicents.protocols.ss7.map.api.service.pdpContextActivation.MAPServicePdpContextActivationListener;
import org.mobicents.protocols.ss7.map.api.service.pdpContextActivation.SendRoutingInfoForGprsRequest;
import org.mobicents.protocols.ss7.map.api.service.pdpContextActivation.SendRoutingInfoForGprsResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.*;
import org.mobicents.protocols.ss7.map.api.service.supplementary.*;
import org.mobicents.protocols.ss7.map.api.smstpdu.*;
import org.mobicents.protocols.ss7.map.primitives.IMEIImpl;
import org.mobicents.protocols.ss7.map.primitives.IMSIImpl;
import org.mobicents.protocols.ss7.map.primitives.LMSIImpl;
import org.mobicents.protocols.ss7.map.primitives.MAPExtensionContainerImpl;
import org.mobicents.protocols.ss7.map.service.mobility.MAPDialogMobilityImpl;
import org.mobicents.protocols.ss7.map.service.mobility.subscriberInformation.RequestedInfoImpl;
import org.mobicents.protocols.ss7.map.service.mobility.subscriberManagement.SupportedCamelPhasesImpl;
import org.mobicents.protocols.ss7.map.service.mobility.subscriberManagement.TeleserviceCodeImpl;
import org.mobicents.protocols.ss7.map.service.oam.TraceReferenceImpl;
import org.mobicents.protocols.ss7.map.service.oam.TraceTypeImpl;
import org.mobicents.protocols.ss7.map.smstpdu.*;
import org.mobicents.protocols.ss7.tcap.asn.comp.Problem;
import org.mobicents.protocols.ss7.tools.simulator.AttackSimulationOrganizer;
import org.mobicents.protocols.ss7.tools.simulator.Stoppable;
import org.mobicents.protocols.ss7.tools.simulator.common.AddressNatureType;
import org.mobicents.protocols.ss7.tools.simulator.common.AttackTesterBase;
import org.mobicents.protocols.ss7.tools.simulator.level2.IsupMan;
import org.mobicents.protocols.ss7.tools.simulator.level3.MapMan;
import org.mobicents.protocols.ss7.tools.simulator.level3.MapProtocolVersion;
import org.mobicents.protocols.ss7.tools.simulator.level3.NumberingPlanMapType;
import org.mobicents.protocols.ss7.tools.simulator.management.AttackTesterHost;
import org.mobicents.protocols.ss7.tools.simulator.management.DialogInfo;
import org.mobicents.protocols.ss7.tools.simulator.management.Instance_L2;
import org.mobicents.protocols.ss7.tools.simulator.management.Subscriber;
import org.mobicents.protocols.ss7.tools.simulator.tests.sms.*;

import javax.xml.stream.Location;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Random;

/**
 * @author Kristoffer Jensen
 */
public class TestAttackClient extends AttackTesterBase implements Stoppable, MAPDialogListener, MAPServiceSmsListener,
        MAPServiceMobilityListener, MAPServiceCallHandlingListener, MAPServiceOamListener, MAPServiceSupplementaryListener,
        MAPServicePdpContextActivationListener, ISUPListener {

    public static String SOURCE_NAME = "TestAttackClient";

    private final String name;
    private MapMan mapMan;
    private IsupMan isupMan;

    private boolean isStarted = false;
    private int countSriReq = 0;
    private int countSriResp = 0;
    private int countMtFsmReq = 0;
    private int countMtFsmReqNot = 0;
    private int countMtFsmResp = 0;
    private int countMoFsmReq = 0;
    private int countMoFsmResp = 0;
    private int countIscReq = 0;
    private int countRsmdsReq = 0;
    private int countRsmdsResp = 0;
    private int countAscReq = 0;
    private int countAscResp = 0;
    private int countErrRcvd = 0;
    private int countErrSent = 0;
    private String currentRequestDef = "";
    private boolean needSendSend = false;
    private boolean needSendClose = false;
    private int mesRef = 0;

    private static Charset isoCharset = Charset.forName("ISO-8859-1");
    private ProvideSubscriberInfoResponse psiResponse;
    private SendRoutingInfoForSMResponse sriResponse;
    private AnyTimeInterrogationResponse atiResponse;
    private ProvideRoamingNumberResponse lastProvideRoamingNumberResponse;
    private MtForwardShortMessageResponse lastMtForwardShortMessageResponse;
    private RegisterSSResponse lastRegisterSSResponse;
    private EraseSSResponse lastEraseSSResponse;
    private SendRoutingInformationResponse lastSendRoutingInfoResponse;
    private InsertSubscriberDataResponse lastInsertSubscriberDataResponse;
    private CancelLocationResponse lastCancelLocationResponse;
    private ActivateTraceModeResponse_Mobility lastActivateTraceModeResponse;
    private UpdateLocationResponse lastUpdateLocationResponse;

    public TestAttackClient() {
        super(SOURCE_NAME);
        this.name = "???";
    }

    public TestAttackClient(String name) {
        super(SOURCE_NAME);
        this.name = name;
    }

    public void setTesterHost(AttackTesterHost testerHost) {
        this.testerHost = testerHost;
    }

    public void setMapMan(MapMan val) {
        this.mapMan = val;
    }

    public AddressNatureType getAddressNature() {
        return new AddressNatureType(this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getAddressNature().getIndicator());
    }

    public String getAddressNature_Value() {
        return new AddressNatureType(this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getAddressNature().getIndicator()).toString();
    }

    public void setAddressNature(AddressNatureType val) {
        this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().setAddressNature(AddressNature.getInstance(val.intValue()));
        this.testerHost.markStore();
    }

    public NumberingPlanMapType getNumberingPlan() {
        return new NumberingPlanMapType(this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getNumberingPlan().getIndicator());
    }

    public String getNumberingPlan_Value() {
        return new NumberingPlanMapType(this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getNumberingPlan().getIndicator())
                .toString();
    }

    public void setNumberingPlan(NumberingPlanMapType val) {
        this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().setNumberingPlan(NumberingPlan.getInstance(val.intValue()));
        this.testerHost.markStore();
    }

    public String getServiceCenterAddress() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getServiceCenterAddress();
    }

    public void setServiceCenterAddress(String val) {
        this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().setServiceCenterAddress(val);
        this.testerHost.markStore();
    }

    public MapProtocolVersion getMapProtocolVersion() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getMapProtocolVersion();
    }

    public String getMapProtocolVersion_Value() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getMapProtocolVersion().toString();
    }

    public void setMapProtocolVersion(MapProtocolVersion val) {
        this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().setMapProtocolVersion(val);
        this.testerHost.markStore();
    }

    public SRIReaction getSRIReaction() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getSRIReaction();
    }

    public String getSRIReaction_Value() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getSRIReaction().toString();
    }

    public void setSRIReaction(SRIReaction val) {
        this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().setSRIReaction(val);
        this.testerHost.markStore();
    }

    public SRIInformServiceCenter getSRIInformServiceCenter() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getSRIInformServiceCenter();
    }

    public String getSRIInformServiceCenter_Value() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getSRIInformServiceCenter().toString();
    }

    public void setSRIInformServiceCenter(SRIInformServiceCenter val) {
        this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().setSRIInformServiceCenter(val);
        this.testerHost.markStore();
    }

    public boolean isSRIScAddressNotIncluded() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().isSRIScAddressNotIncluded();
    }

    public void setSRIScAddressNotIncluded(boolean val) {
        this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().setSRIScAddressNotIncluded(val);
        this.testerHost.markStore();
    }

    public MtFSMReaction getMtFSMReaction() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getMtFSMReaction();
    }

    public String getMtFSMReaction_Value() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getMtFSMReaction().toString();
    }

    public void setMtFSMReaction(MtFSMReaction val) {
        this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().setMtFSMReaction(val);
        this.testerHost.markStore();
    }

    public ReportSMDeliveryStatusReaction getReportSMDeliveryStatusReaction() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getReportSMDeliveryStatusReaction();
    }

    public String getReportSMDeliveryStatusReaction_Value() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getReportSMDeliveryStatusReaction().toString();
    }

    public void setReportSMDeliveryStatusReaction(ReportSMDeliveryStatusReaction val) {
        this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().setReportSMDeliveryStatusReaction(val);
        this.testerHost.markStore();
    }

    public void putReportSMDeliveryStatusReaction(String val) {
        ReportSMDeliveryStatusReaction x = ReportSMDeliveryStatusReaction.createInstance(val);
        if (x != null)
            this.setReportSMDeliveryStatusReaction(x);
    }

    public boolean isOneNotificationFor100Dialogs() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().isOneNotificationFor100Dialogs();
    }

    public void setOneNotificationFor100Dialogs(boolean val) {
        this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().setOneNotificationFor100Dialogs(val);
        this.testerHost.markStore();
    }

    public boolean isReturn20PersDeliveryErrors() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().isReturn20PersDeliveryErrors();
    }

    public void setReturn20PersDeliveryErrors(boolean val) {
        this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().setReturn20PersDeliveryErrors(val);
        this.testerHost.markStore();
    }

    public boolean isContinueDialog() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().isContinueDialog();
    }

    public void setContinueDialog(boolean val) {
        this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().setContinueDialog(val);
        this.testerHost.markStore();
    }

    public void putSRIReaction(String val) {
        SRIReaction x = SRIReaction.createInstance(val);
        if (x != null)
            this.setSRIReaction(x);
    }

    public void putSRIInformServiceCenter(String val) {
        SRIInformServiceCenter x = SRIInformServiceCenter.createInstance(val);
        if (x != null)
            this.setSRIInformServiceCenter(x);
    }

    public void putMtFSMReaction(String val) {
        MtFSMReaction x = MtFSMReaction.createInstance(val);
        if (x != null)
            this.setMtFSMReaction(x);
    }

    public String getSRIResponseImsi() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getSriResponseImsi();
    }

    public void setSRIResponseImsi(String val) {
        this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().setSriResponseImsi(val);
        this.testerHost.markStore();
    }

    public String getSRIResponseVlr() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getSriResponseVlr();
    }

    public void setSRIResponseVlr(String val) {
        this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().setSriResponseVlr(val);
        this.testerHost.markStore();
    }

    public int getSmscSsn() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getSmscSsn();
    }

    public void setSmscSsn(int val) {
        this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().setSmscSsn(val);
        this.testerHost.markStore();
    }

    public int getNationalLanguageCode() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getNationalLanguageCode();
    }

    public void setNationalLanguageCode(int val) {
        this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().setNationalLanguageCode(val);
        this.testerHost.markStore();
    }

    public TypeOfNumberType getTypeOfNumber() {
        return new TypeOfNumberType(this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getTypeOfNumber().getCode());
    }

    public String getTypeOfNumber_Value() {
        return new TypeOfNumberType(this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getTypeOfNumber().getCode()).toString();
    }

    public void setTypeOfNumber(TypeOfNumberType val) {
        this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().setTypeOfNumber(TypeOfNumber.getInstance(val.intValue()));
        this.testerHost.markStore();
    }

    public NumberingPlanIdentificationType getNumberingPlanIdentification() {
        return new NumberingPlanIdentificationType(this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getNumberingPlanIdentification()
                .getCode());
    }

    public String getNumberingPlanIdentification_Value() {
        return new NumberingPlanIdentificationType(this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getNumberingPlanIdentification()
                .getCode()).toString();
    }

    public void setNumberingPlanIdentification(NumberingPlanIdentificationType val) {
        this.testerHost.getConfigurationData().getTestAttackClientConfigurationData()
                .setNumberingPlanIdentification(NumberingPlanIdentification.getInstance(val.intValue()));
        this.testerHost.markStore();
    }

    public SmsCodingType getSmsCodingType() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getSmsCodingType();
    }

    public String getSmsCodingType_Value() {
        return this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getSmsCodingType().toString();
    }

    public void setSmsCodingType(SmsCodingType val) {
        this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().setSmsCodingType(val);
        this.testerHost.markStore();
    }

    public void putAddressNature(String val) {
        AddressNatureType x = AddressNatureType.createInstance(val);
        if (x != null)
            this.setAddressNature(x);
    }

    public void putNumberingPlan(String val) {
        NumberingPlanMapType x = NumberingPlanMapType.createInstance(val);
        if (x != null)
            this.setNumberingPlan(x);
    }

    public void putMapProtocolVersion(String val) {
        MapProtocolVersion x = MapProtocolVersion.createInstance(val);
        if (x != null)
            this.setMapProtocolVersion(x);
    }

    public void putTypeOfNumber(String val) {
        TypeOfNumberType x = TypeOfNumberType.createInstance(val);
        if (x != null)
            this.setTypeOfNumber(x);
    }

    public void putNumberingPlanIdentification(String val) {
        NumberingPlanIdentificationType x = NumberingPlanIdentificationType.createInstance(val);
        if (x != null)
            this.setNumberingPlanIdentification(x);
    }

    public void putSmsCodingType(String val) {
        SmsCodingType x = SmsCodingType.createInstance(val);
        if (x != null)
            this.setSmsCodingType(x);
    }

    public String getCurrentRequestDef() {
        return "LastDialog: " + currentRequestDef;
    }

    @Override
    public String getState() {
        StringBuilder sb = new StringBuilder();
        sb.append("<html>");
        sb.append(SOURCE_NAME);
        sb.append(": ");
        sb.append("<br>Count: countSriReq-");
        sb.append(countSriReq);
        sb.append(", countSriResp-");
        sb.append(countSriResp);
        sb.append("<br>countMtFsmReq-");
        sb.append(countMtFsmReq);
        sb.append(", countMtFsmResp-");
        sb.append(countMtFsmResp);
        sb.append("<br>countMoFsmReq-");
        sb.append(countMoFsmReq);
        sb.append(", countMoFsmResp-");
        sb.append(countMoFsmResp);
        sb.append(", countIscReq-");
        sb.append(countIscReq);
        sb.append("<br>countRsmdsReq-");
        sb.append(countRsmdsReq);
        sb.append(", countRsmdsResp-");
        sb.append(countRsmdsResp);
        sb.append(", countAscReq-");
        sb.append(countAscReq);
        sb.append("<br>countAscResp-");
        sb.append(countAscResp);
        sb.append(", countErrRcvd-");
        sb.append(countErrRcvd);
        sb.append(", countErrSent-");
        sb.append(countErrSent);
        sb.append("</html>");
        return sb.toString();
    }

    public boolean start() {
        this.countSriReq = 0;
        this.countSriResp = 0;
        this.countMtFsmReq = 0;
        this.countMtFsmReqNot = 0;
        this.countMtFsmResp = 0;
        this.countMoFsmReq = 0;
        this.countMoFsmResp = 0;
        this.countIscReq = 0;
        this.countRsmdsReq = 0;
        this.countRsmdsResp = 0;
        this.countAscReq = 0;
        this.countAscResp = 0;
        this.countErrRcvd = 0;
        this.countErrSent = 0;

        if(this.testerHost.getInstance_L2().intValue() == Instance_L2.VAL_SCCP) {
            MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();

            mapProvider.getMAPServiceSms().acivate();
            mapProvider.getMAPServiceSms().addMAPServiceListener(this);

            mapProvider.getMAPServiceMobility().acivate();
            mapProvider.getMAPServiceMobility().addMAPServiceListener(this);

            mapProvider.getMAPServiceCallHandling().acivate();
            mapProvider.getMAPServiceCallHandling().addMAPServiceListener(this);

            mapProvider.getMAPServiceOam().acivate();
            mapProvider.getMAPServiceOam().addMAPServiceListener(this);

            mapProvider.getMAPServiceSupplementary().acivate();
            mapProvider.getMAPServiceSupplementary().addMAPServiceListener(this);

            mapProvider.getMAPServicePdpContextActivation().acivate();
            mapProvider.getMAPServicePdpContextActivation().addMAPServiceListener(this);

            mapProvider.addMAPDialogListener(this);
        } else {
            //ISUPProvider isupProvider = this.testerHost.getIsupMan().getIsupStack().getIsupProvider();
            //isupProvider.addListener(this);
        }

        this.testerHost.sendNotif(SOURCE_NAME, "AttackClient has been started", "", Level.INFO);
        isStarted = true;

        return true;
    }

    @Override
    public void stop() {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        isStarted = false;
        mapProvider.getMAPServiceSms().deactivate();
        mapProvider.getMAPServiceSms().removeMAPServiceListener(this);
        mapProvider.removeMAPDialogListener(this);
        this.testerHost.sendNotif(SOURCE_NAME, "AttackClient has been stopped", "", Level.INFO);
    }

    @Override
    public void execute() {
    }

    public String closeCurrentDialog() {
        // TODO Auto-generated method stub
        return null;
    }

    public DialogInfo performMoForwardSM(String msg, String destIsdnNumber, String origIsdnNumber, String serviceCentreAddress) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPParameterFactory parameterFactory = mapProvider.getMAPParameterFactory();

        MAPApplicationContext applicationContext = MAPApplicationContext.getInstance(
                MAPApplicationContextName.shortMsgMORelayContext,
                MAPApplicationContextVersion.version3);

        AddressString serviceCentreAddressDA = mapProvider.getMAPParameterFactory().createAddressString(
                this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getAddressNature(),
                this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getNumberingPlan(), serviceCentreAddress);
        SM_RP_DA da = mapProvider.getMAPParameterFactory().createSM_RP_DA(serviceCentreAddressDA);

        ISDNAddressString msisdn = mapProvider.getMAPParameterFactory().createISDNAddressString(
                this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getAddressNature(),
                this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getNumberingPlan(), origIsdnNumber);
        SM_RP_OA oa = mapProvider.getMAPParameterFactory().createSM_RP_OA_Msisdn(msisdn);


        AddressField destAddress = new AddressFieldImpl(this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getTypeOfNumber(),
                this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getNumberingPlanIdentification(), destIsdnNumber);

        int dcsVal = 4; //GSM-8
        DataCodingScheme dcs = new DataCodingSchemeImpl(dcsVal);
        UserDataHeader udh = null;
        if (dcs.getCharacterSet() == CharacterSet.GSM8) {
            ApplicationPortAddressing16BitAddressImpl apa16 = new ApplicationPortAddressing16BitAddressImpl(16020, 0);
            udh = new UserDataHeaderImpl();
            udh.addInformationElement(apa16);
        }

        UserData userData = new UserDataImpl(msg, dcs, udh, isoCharset);
        ProtocolIdentifier pi = new ProtocolIdentifierImpl(0);
        ValidityPeriod validityPeriod = new ValidityPeriodImpl(169); // 3 days
        SmsSubmitTpdu tpdu = new SmsSubmitTpduImpl(false, false, false, ++mesRef, destAddress, pi, validityPeriod, userData);

        try {
            MAPDialogSms curDialog = mapProvider.getMAPServiceSms().createNewDialog(
                applicationContext,
                    this.mapMan.createOrigAddress(),
                    null,
                    this.mapMan.createDestAddress(),
                    null);

            SmsSignalInfo si = mapProvider.getMAPParameterFactory().createSmsSignalInfo(tpdu, null);

            long invokeId = curDialog.addMoForwardShortMessageRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, da, oa, si, null, null);
            curDialog.send();
            long remoteDialogId = curDialog.getLocalDialogId();
            return new DialogInfo(invokeId, remoteDialogId);
        } catch (MAPException e) {
            System.out.println("Error when sending MoForwardSMReq: " + e.toString());
            return null;
        }
    }

    public String performMoForwardSMPartial(String msg, String destIsdnNumber, String origIsdnNumber, int msgRef, int segmCnt, int segmNum) {
        if (!isStarted)
            return "The tester is not started";
        if (msg == null || msg.equals(""))
            return "Msg is empty";
        if (destIsdnNumber == null || destIsdnNumber.equals(""))
            return "DestIsdnNumber is empty";
        if (origIsdnNumber == null || origIsdnNumber.equals(""))
            return "OrigIsdnNumber is empty";

        if (msgRef < 0 || msgRef > 255)
            return "msgRef must has value 0-255";
        if (segmCnt < 1 || segmCnt > 255)
            return "segmCnt must has value 1-255";
        if (segmNum < 1 || segmNum > 255)
            return "segmNum must has value 1-255";
        if (segmCnt == 1)
            segmCnt = 0;

        int maxMsgLen = this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getSmsCodingType()
                .getSupportesMaxMessageLength(segmCnt > 1 ? 6 : 0);
        if (msg.length() > maxMsgLen)
            return "Simulator does not support message length for current encoding type and segmentation state more than " + maxMsgLen;

        currentRequestDef = "";

        return doMoForwardSM(msg, destIsdnNumber, origIsdnNumber, this.getServiceCenterAddress(), msgRef, segmCnt, segmNum);
    }

    private String doMoForwardSM(String msg, String destIsdnNumber, String origIsdnNumber, String serviceCentreAddr, int msgRef, int segmCnt, int segmNum) {

        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();

        MAPApplicationContextVersion vers;
        MAPApplicationContextName acn = MAPApplicationContextName.shortMsgMORelayContext;
        switch (this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getMapProtocolVersion().intValue()) {
            case MapProtocolVersion.VAL_MAP_V1:
                vers = MAPApplicationContextVersion.version1;
                break;
            case MapProtocolVersion.VAL_MAP_V2:
                vers = MAPApplicationContextVersion.version2;
                break;
            default:
                vers = MAPApplicationContextVersion.version3;
                break;
        }
        MAPApplicationContext mapAppContext = MAPApplicationContext.getInstance(acn, vers);

        AddressString serviceCentreAddressDA = mapProvider.getMAPParameterFactory().createAddressString(
                this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getAddressNature(),
                this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getNumberingPlan(), serviceCentreAddr);
        SM_RP_DA da = mapProvider.getMAPParameterFactory().createSM_RP_DA(serviceCentreAddressDA);
        ISDNAddressString msisdn = mapProvider.getMAPParameterFactory().createISDNAddressString(
                this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getAddressNature(),
                this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getNumberingPlan(), origIsdnNumber);
        SM_RP_OA oa = mapProvider.getMAPParameterFactory().createSM_RP_OA_Msisdn(msisdn);

        try {
            AddressField destAddress = new AddressFieldImpl(this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getTypeOfNumber(),
                    this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getNumberingPlanIdentification(), destIsdnNumber);

            int dcsVal = 0;
            switch (this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getSmsCodingType().intValue()) {
                case SmsCodingType.VAL_GSM7:
                    dcsVal = 0;
                    break;
                case SmsCodingType.VAL_GSM8:
                    dcsVal = 4;
                    break;
                case SmsCodingType.VAL_UCS2:
                    dcsVal = 8;
                    break;
            }
            DataCodingScheme dcs = new DataCodingSchemeImpl(dcsVal);
            UserDataHeader udh = null;
            if (dcs.getCharacterSet() == CharacterSet.GSM8) {
                ApplicationPortAddressing16BitAddressImpl apa16 = new ApplicationPortAddressing16BitAddressImpl(16020, 0);
                udh = new UserDataHeaderImpl();
                udh.addInformationElement(apa16);
            }
            if (segmCnt > 1) {
                if (udh == null)
                    udh = new UserDataHeaderImpl();
                udh.addInformationElement(new ConcatenatedShortMessagesIdentifierImpl(false, msgRef, segmCnt, segmNum));
            }
            if (dcs.getCharacterSet() == CharacterSet.GSM7
                    && this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getNationalLanguageCode() > 0) {
                NationalLanguageIdentifier nli = NationalLanguageIdentifier.getInstance(this.testerHost.getConfigurationData()
                        .getTestAttackClientConfigurationData().getNationalLanguageCode());
                if (nli != null) {
                    if (udh == null)
                        udh = new UserDataHeaderImpl();
                    udh.addInformationElement(new NationalLanguageLockingShiftIdentifierImpl(nli));
                    udh.addInformationElement(new NationalLanguageSingleShiftIdentifierImpl(nli));
                }
            }

            UserData userData = new UserDataImpl(msg, dcs, udh, isoCharset);
            ProtocolIdentifier pi = new ProtocolIdentifierImpl(0);
            ValidityPeriod validityPeriod = new ValidityPeriodImpl(169); // 3
            // days
            SmsSubmitTpdu tpdu = new SmsSubmitTpduImpl(false, false, false, ++mesRef, destAddress, pi, validityPeriod, userData);
            SmsSignalInfo si = mapProvider.getMAPParameterFactory().createSmsSignalInfo(tpdu, null);

            MAPDialogSms curDialog = mapProvider.getMAPServiceSms().createNewDialog(mapAppContext, this.mapMan.createOrigAddress(), null,
                    this.mapMan.createDestAddress(serviceCentreAddr, this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getSmscSsn()),
                    null);

            if (si.getData().length < 110 || vers == MAPApplicationContextVersion.version1) {
                if (this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getMapProtocolVersion().intValue() <= 2)
                    curDialog.addForwardShortMessageRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, da, oa, si, false);
                else
                    curDialog.addMoForwardShortMessageRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, da, oa, si, null, null);
                curDialog.send();

                String mtData = createMoData(curDialog.getLocalDialogId(), destIsdnNumber, origIsdnNumber, serviceCentreAddr);
                currentRequestDef += "Sent moReq;";
                this.countMoFsmReq++;
                this.testerHost.sendNotif(SOURCE_NAME, "Sent: moReq: " + msg, mtData, Level.DEBUG);
            } else {
                ResendMessageData md = new ResendMessageData();
                md.da = da;
                md.oa = oa;
                md.si = si;
                md.destIsdnNumber = destIsdnNumber;
                md.origIsdnNumber = origIsdnNumber;
                md.serviceCentreAddr = serviceCentreAddr;
                md.msg = msg;
                curDialog.setUserObject(md);

                curDialog.send();
                currentRequestDef += "Sent emptTBegin;";
                this.testerHost.sendNotif(SOURCE_NAME, "Sent: emptTBegin", "", Level.DEBUG);
            }

            return "MoForwardShortMessageRequest has been sent";
        } catch (MAPException ex) {
            return "Exception when sending MoForwardShortMessageRequest: " + ex.toString();
        }
    }

    private String createMoData(long dialogId, String destIsdnNumber, String origIsdnNumber, String serviceCentreAddr) {
        StringBuilder sb = new StringBuilder();
        sb.append("dialogId=");
        sb.append(dialogId);
        sb.append(", destIsdnNumber=\"");
        sb.append(destIsdnNumber);
        sb.append(", origIsdnNumber=\"");
        sb.append(origIsdnNumber);
        sb.append("\", serviceCentreAddr=\"");
        sb.append(serviceCentreAddr);
        sb.append("\"");
        return sb.toString();
    }

    public void performAlertServiceCentre(ISDNAddressString msisdn, String serviceCentreAddress) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPApplicationContext applicationContext = MAPApplicationContext.getInstance(
                MAPApplicationContextName.shortMsgAlertContext,
                MAPApplicationContextVersion.version2);

        AddressString scAddress = mapProvider.getMAPParameterFactory().createAddressString(
                this.testerHost.getAttackSimulationOrganizer().getDefaultSmscAddress().getAddressNature(),
                this.testerHost.getAttackSimulationOrganizer().getDefaultSmscAddress().getNumberingPlan(),
                serviceCentreAddress);

        try {
            MAPDialogSms curDialog = mapProvider.getMAPServiceSms().createNewDialog(applicationContext,
                    this.mapMan.createOrigAddress(),
                    null,
                    this.mapMan.createDestAddress(),
                    null);

            curDialog.addAlertServiceCentreRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, msisdn, scAddress);
            curDialog.send();
        } catch (MAPException e) {
            System.out.println("Error when sending AlertServiceCentre: " + e.toString());
        }
    }

    private String doAlertServiceCentre(String destIsdnNumber, String serviceCentreAddr) {

        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();

        MAPApplicationContextVersion vers;
        MAPApplicationContextName acn = MAPApplicationContextName.shortMsgAlertContext;
        switch (this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getMapProtocolVersion().intValue()) {
            case MapProtocolVersion.VAL_MAP_V1:
                vers = MAPApplicationContextVersion.version1;
                break;
            default:
                vers = MAPApplicationContextVersion.version2;
                break;
        }
        MAPApplicationContext mapAppContext = MAPApplicationContext.getInstance(acn, vers);

        try {
            ISDNAddressString msisdn = mapProvider.getMAPParameterFactory().createISDNAddressString(
                    this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getAddressNature(),
                    this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getNumberingPlan(), destIsdnNumber);
            AddressString serviceCentreAddressDA = mapProvider.getMAPParameterFactory().createAddressString(
                    this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getAddressNature(),
                    this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getNumberingPlan(), serviceCentreAddr);

            MAPDialogSms curDialog = mapProvider.getMAPServiceSms().createNewDialog(mapAppContext, this.mapMan.createOrigAddress(), null,
                    this.mapMan.createDestAddress(serviceCentreAddr, this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getSmscSsn()),
                    null);

            curDialog.addAlertServiceCentreRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, msisdn, serviceCentreAddressDA);
            curDialog.send();
            if (vers == MAPApplicationContextVersion.version1)
                curDialog.release();

            String ascData = "isdnNumber=" + destIsdnNumber + ", serviceCentreAddr=" + serviceCentreAddr;
            currentRequestDef += "Sent ascReq;";
            this.countAscReq++;
            this.testerHost.sendNotif(SOURCE_NAME, "Sent: ascReq", ascData, Level.DEBUG);

            return "AlertServiceCentreRequest has been sent";
        } catch (MAPException ex) {
            return "Exception when sending AlertServiceCentreRequest: " + ex.toString();
        }
    }

    @Override
    public void onForwardShortMessageRequest(ForwardShortMessageRequest ind) {
        if (!isStarted)
            return;

        MAPDialogSms curDialog = ind.getMAPDialog();
        long invokeId = ind.getInvokeId();
        SM_RP_DA da = ind.getSM_RP_DA();
        SM_RP_OA oa = ind.getSM_RP_OA();
        SmsSignalInfo si = ind.getSM_RP_UI();

        if (da.getIMSI() != null || da.getLMSI() != null) { // mt message
            this.onMtRequest(da, oa, si, curDialog);

            try {
                MtFSMReaction mtFSMReaction = this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getMtFSMReaction();

                Random rnd = new Random();
                if (this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().isReturn20PersDeliveryErrors()) {
                    int n = rnd.nextInt(5);
                    if (n == 0) {
                        n = rnd.nextInt(5);
                        mtFSMReaction = new MtFSMReaction(n + 2);
                    } else {
                        mtFSMReaction = new MtFSMReaction(MtFSMReaction.VAL_RETURN_SUCCESS);
                    }
                }

                if (mtFSMReaction.intValue() == MtFSMReaction.VAL_RETURN_SUCCESS) {
                    curDialog.addForwardShortMessageResponse(invokeId);
                    this.countMtFsmResp++;

                    if (!this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().isOneNotificationFor100Dialogs()) {
                        this.testerHost.sendNotif(SOURCE_NAME, "Sent: mtResp", "", Level.DEBUG);
                    }

                    if (this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().isContinueDialog())
                        this.needSendSend = true;
                    else
                        this.needSendClose = true;
                } else {
                    sendMtError(curDialog, invokeId, mtFSMReaction);
                    this.needSendClose = true;
                }

            } catch (MAPException e) {
                this.testerHost.sendNotif(SOURCE_NAME, "Exception when invoking addMtForwardShortMessageResponse : " + e.getMessage(), e, Level.ERROR);
            }
        }
    }

    private void sendMtError(MAPDialogSms curDialog, long invokeId, MtFSMReaction mtFSMReaction) throws MAPException {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        String uData;
        switch (mtFSMReaction.intValue()) {
            case MtFSMReaction.VAL_ERROR_MEMORY_CAPACITY_EXCEEDED:
            case MtFSMReaction.VAL_ERROR_UNKNOWN_SERVICE_CENTRE:
                SMEnumeratedDeliveryFailureCause smEnumeratedDeliveryFailureCause;
                if (this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getMtFSMReaction().intValue() == MtFSMReaction.VAL_ERROR_MEMORY_CAPACITY_EXCEEDED)
                    smEnumeratedDeliveryFailureCause = SMEnumeratedDeliveryFailureCause.memoryCapacityExceeded;
                else
                    smEnumeratedDeliveryFailureCause = SMEnumeratedDeliveryFailureCause.unknownServiceCentre;
                MAPErrorMessage mapErrorMessage = mapProvider.getMAPErrorMessageFactory()
                        .createMAPErrorMessageSMDeliveryFailure(
                                curDialog.getApplicationContext().getApplicationContextVersion().getVersion(),
                                smEnumeratedDeliveryFailureCause, null, null);
                curDialog.sendErrorComponent(invokeId, mapErrorMessage);

                this.countErrSent++;
                uData = this.createErrorData(curDialog.getLocalDialogId(), (int) invokeId, mapErrorMessage);
                this.testerHost.sendNotif(SOURCE_NAME, "Sent: errSmDelFail", uData, Level.DEBUG);
                break;
            case MtFSMReaction.VAL_ERROR_ABSENT_SUBSCRIBER:
                mapErrorMessage = null;
                switch (curDialog.getApplicationContext().getApplicationContextVersion()) {
                    case version1:
                        mapErrorMessage = mapProvider.getMAPErrorMessageFactory().createMAPErrorMessageAbsentSubscriber(null);
                        break;
                    case version2:
                        mapErrorMessage = mapProvider.getMAPErrorMessageFactory().createMAPErrorMessageAbsentSubscriber(null, null);
                        break;
                    default:
                        mapErrorMessage = mapProvider.getMAPErrorMessageFactory().createMAPErrorMessageAbsentSubscriberSM(AbsentSubscriberDiagnosticSM.IMSIDetached,
                                null, null);
                        break;
                }

                curDialog.sendErrorComponent(invokeId, mapErrorMessage);

                this.countErrSent++;
                uData = this.createErrorData(curDialog.getLocalDialogId(), (int) invokeId, mapErrorMessage);
                this.testerHost.sendNotif(SOURCE_NAME, "Sent: errAbsSubs", uData, Level.DEBUG);
                break;
            case MtFSMReaction.VAL_ERROR_SUBSCRIBER_BUSY_FOR_MT_SMS:
                mapErrorMessage = mapProvider.getMAPErrorMessageFactory().createMAPErrorMessageSubscriberBusyForMtSms(null, null);
                curDialog.sendErrorComponent(invokeId, mapErrorMessage);

                this.countErrSent++;
                uData = this.createErrorData(curDialog.getLocalDialogId(), (int) invokeId, mapErrorMessage);
                this.testerHost.sendNotif(SOURCE_NAME, "Sent: errSubBusyForMt", uData, Level.DEBUG);
                break;
            case MtFSMReaction.VAL_ERROR_SYSTEM_FAILURE:
                mapErrorMessage = mapProvider.getMAPErrorMessageFactory().createMAPErrorMessageSystemFailure(
                        (long) curDialog.getApplicationContext().getApplicationContextVersion().getVersion(), NetworkResource.vmsc, null, null);
                curDialog.sendErrorComponent(invokeId, mapErrorMessage);

                this.countErrSent++;
                uData = this.createErrorData(curDialog.getLocalDialogId(), (int) invokeId, mapErrorMessage);
                this.testerHost.sendNotif(SOURCE_NAME, "Sent: errSysFail", uData, Level.DEBUG);
                break;
        }
    }

    private void onMtRequest(SM_RP_DA da, SM_RP_OA oa, SmsSignalInfo si, MAPDialogSms curDialog) {

        this.countMtFsmReq++;

        si.setGsm8Charset(isoCharset);
        String destImsi = null;
        if (da != null) {
            IMSI imsi = da.getIMSI();
            if (imsi != null)
                destImsi = imsi.getData();
        }
        AddressString serviceCentreAddr = null;

        if (oa != null) {
            serviceCentreAddr = oa.getServiceCentreAddressOA();
        }

        try {
            String msg = null;
            SmsDeliverTpdu dTpdu = null;
            if (si != null) {
                SmsTpdu tpdu = si.decodeTpdu(false);
                if (tpdu instanceof SmsDeliverTpdu) {
                    dTpdu = (SmsDeliverTpdu) tpdu;
                    UserData ud = dTpdu.getUserData();
                    if (ud != null) {
                        ud.decode();
                        msg = ud.getDecodedMessage();

                        UserDataHeader udh = ud.getDecodedUserDataHeader();
                        if (udh != null) {
                            StringBuilder sb = new StringBuilder();
                            sb.append("[");
                            int i2 = 0;
                            for (byte b : udh.getEncodedData()) {
                                int i1 = (b & 0xFF);
                                if (i2 == 0)
                                    i2 = 1;
                                else
                                    sb.append(", ");
                                sb.append(i1);
                            }
                            sb.append("] ");
                            msg = sb.toString() + msg;
                        }
                    }
                }
            }

            if (this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().isOneNotificationFor100Dialogs()) {
                int i1 = countMtFsmReq / 100;
                if (countMtFsmReqNot < i1) {
                    countMtFsmReqNot = i1;
                    this.testerHost.sendNotif(SOURCE_NAME, "Rsvd: Ms messages: " + (countMtFsmReqNot * 100), "", Level.DEBUG);
                }
            } else {
                String uData = this.createMtData(curDialog, destImsi, dTpdu, serviceCentreAddr);
                this.testerHost.sendNotif(SOURCE_NAME, "Rcvd: mtReq: " + msg, uData, Level.DEBUG);
            }
        } catch (MAPException e) {
            this.testerHost.sendNotif(SOURCE_NAME, "Exception when decoding MtForwardShortMessageRequest tpdu : " + e.getMessage(), e, Level.ERROR);
        }
    }

    @Override
    public void onForwardShortMessageResponse(ForwardShortMessageResponse ind) {
        if (!isStarted)
            return;

        this.countMoFsmResp++;

        MAPDialogSms curDialog = ind.getMAPDialog();
        long invokeId = curDialog.getLocalDialogId();
        currentRequestDef += "Rsvd moResp;";
        this.testerHost.sendNotif(SOURCE_NAME, "Rcvd: moResp", "", Level.DEBUG);
    }

    @Override
    public void onMoForwardShortMessageRequest(MoForwardShortMessageRequest moForwSmInd) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onMoForwardShortMessageResponse(MoForwardShortMessageResponse ind) {
        if (!isStarted)
            return;

        this.countMoFsmResp++;

        MAPDialogSms curDialog = ind.getMAPDialog();
        long invokeId = curDialog.getLocalDialogId();
        currentRequestDef += "Rsvd moResp;";
        this.testerHost.sendNotif(SOURCE_NAME, "Rcvd: moResp", "", Level.DEBUG);
    }

    @Override
    public void onMtForwardShortMessageRequest(MtForwardShortMessageRequest ind) {
        MAPDialogSms curDialog = ind.getMAPDialog();
        long invokeId = ind.getInvokeId();

        try {
            curDialog.addMtForwardShortMessageResponse(invokeId, null, null);
            this.needSendClose = true;
        } catch (MAPException e) {
            System.out.println("Error in onMtForwardShortMessageRequest: " + e.toString());
        }
    }

    public void performMtForwardSM(String msg, IMSI destImsi, String vlrNumber, String origIsdnNumber, String serviceCentreAddr) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPParameterFactory parameterFactory = mapProvider.getMAPParameterFactory();

        AddressField originatingAddress = new AddressFieldImpl(
                this.testerHost.getConfigurationData().getTestAttackServerConfigurationData().getTypeOfNumber(), this.testerHost.getConfigurationData()
                .getTestAttackServerConfigurationData().getNumberingPlanIdentification(), origIsdnNumber);

        MAPApplicationContext applicationContext = MAPApplicationContext.getInstance(
                MAPApplicationContextName.shortMsgMTRelayContext,
                MAPApplicationContextVersion.version3);

        SM_RP_DA da = mapProvider.getMAPParameterFactory().createSM_RP_DA(destImsi);
        AddressString serviceCentreAddress = mapProvider.getMAPParameterFactory().createAddressString(
                this.testerHost.getAttackSimulationOrganizer().getDefaultSmscAddress().getAddressNature(),
                this.testerHost.getAttackSimulationOrganizer().getDefaultSmscAddress().getNumberingPlan(), serviceCentreAddr);
        SM_RP_OA oa = mapProvider.getMAPParameterFactory().createSM_RP_OA_ServiceCentreAddressOA(serviceCentreAddress);

        Calendar cld = new GregorianCalendar();
        int year = cld.get(Calendar.YEAR);
        int mon = cld.get(Calendar.MONTH);
        int day = cld.get(Calendar.DAY_OF_MONTH);
        int h = cld.get(Calendar.HOUR);
        int m = cld.get(Calendar.MINUTE);
        int s = cld.get(Calendar.SECOND);
        int tz = cld.get(Calendar.ZONE_OFFSET);
        AbsoluteTimeStamp serviceCentreTimeStamp = new AbsoluteTimeStampImpl(year - 2000, mon, day, h, m, s, tz / 1000 / 60 / 15);

        int dcsVal = 4; //GSM8
        DataCodingScheme dcs = new DataCodingSchemeImpl(dcsVal);

        UserDataHeader udh = null;
        if (dcs.getCharacterSet() == CharacterSet.GSM8) {
            ApplicationPortAddressing16BitAddressImpl apa16 = new ApplicationPortAddressing16BitAddressImpl(16020, 0);
            udh = new UserDataHeaderImpl();
            udh.addInformationElement(apa16);
        }

        UserData userData = new UserDataImpl(msg, dcs, udh, isoCharset);
        ProtocolIdentifier pi = new ProtocolIdentifierImpl(0);
        SmsDeliverTpdu tpdu = new SmsDeliverTpduImpl(false, false, false, false, originatingAddress, pi, serviceCentreTimeStamp, userData);

        try {
            MAPDialogSms curDialog = mapProvider.getMAPServiceSms().createNewDialog(applicationContext,
                    this.mapMan.createOrigAddress(),
                    null,
                    this.mapMan.createDestAddress(),
                    null);
            SmsSignalInfo si = mapProvider.getMAPParameterFactory().createSmsSignalInfo(tpdu, null);

            curDialog.addMtForwardShortMessageRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, da, oa, si, false, null);
            curDialog.send();
        } catch (MAPException e) {
            System.out.println("Error when sending MtForwardSMReq: " + e.toString());
        }
    }

    public void performMtForwardSmResp(DialogInfo dialogInfo) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPDialogSms curDialog = (MAPDialogSms) mapProvider.getMAPDialog(dialogInfo.remoteDialogId);
        try {
            curDialog.addMtForwardShortMessageResponse(dialogInfo.invokeId, null, null);
            this.needSendClose = true;
        } catch (MAPException e) {
            System.out.println("Error when sending MtForwardSmResp: " + e.toString());
        }
    }

    private String createMtData(MAPDialogSms dialog, String destImsi, SmsDeliverTpdu dTpdu, AddressString serviceCentreAddr) {
        StringBuilder sb = new StringBuilder();
        sb.append("dialogId=");
        sb.append(dialog.getLocalDialogId());
        sb.append(",\ndestImsi=\"");
        sb.append(destImsi);
        sb.append(",\"\nserviceCentreAddr=\"");
        sb.append(serviceCentreAddr);
        sb.append(",\"\nsmsDeliverTpdu=");
        sb.append(dTpdu);

        sb.append(",\nRemoteAddress=");
        sb.append(dialog.getRemoteAddress());
        sb.append(",\nLocalAddress=");
        sb.append(dialog.getLocalAddress());

        return sb.toString();
    }

    @Override
    public void onMtForwardShortMessageResponse(MtForwardShortMessageResponse mtForwSmRespInd) {
        this.lastMtForwardShortMessageResponse = mtForwSmRespInd;
    }

    public MtForwardShortMessageResponse getLastMtForwardSMResponse() {
        return this.lastMtForwardShortMessageResponse;
    }

    public void clearLastMtForwardSMResponse() {
        this.lastMtForwardShortMessageResponse = null;
    }

    @Override
    public void onSendRoutingInfoForSMRequest(SendRoutingInfoForSMRequest ind) {
        if (!isStarted)
            return;

        this.countSriReq++;

        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPDialogSms curDialog = ind.getMAPDialog();
        long invokeId = ind.getInvokeId();

        String uData;
        if (!this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().isOneNotificationFor100Dialogs()) {
            uData = this.createSriData(ind);
            this.testerHost.sendNotif(SOURCE_NAME, "Rcvd: sriReq", uData, Level.DEBUG);
        }

        IMSI imsi = mapProvider.getMAPParameterFactory().createIMSI(
                this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getSriResponseImsi());
        ISDNAddressString networkNodeNumber = mapProvider.getMAPParameterFactory().createISDNAddressString(
                this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getAddressNature(),
                this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getNumberingPlan(),
                this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getSriResponseVlr());
        LocationInfoWithLMSI li = null;
        boolean informServiceCentrePossible = false;

        try {
            SRIReaction sriReaction = this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getSRIReaction();
            Random rnd = new Random();
            if (this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().isReturn20PersDeliveryErrors()) {
                int n = rnd.nextInt(5);
                if (n == 0) {
                    n = rnd.nextInt(4);
                    sriReaction = new SRIReaction(n + 2);
                } else {
                    sriReaction = new SRIReaction(SRIReaction.VAL_RETURN_SUCCESS);
                }
            }

            switch (sriReaction.intValue()) {
                case SRIReaction.VAL_RETURN_SUCCESS:
                    li = mapProvider.getMAPParameterFactory().createLocationInfoWithLMSI(networkNodeNumber, null, null, false, null);
                    curDialog.addSendRoutingInfoForSMResponse(invokeId, imsi, li, null, null);

                    this.countSriResp++;
                    if (!this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().isOneNotificationFor100Dialogs()) {
                        uData = this.createSriRespData(curDialog.getLocalDialogId(), imsi, li);
                        this.testerHost.sendNotif(SOURCE_NAME, "Sent: sriResp", uData, Level.DEBUG);
                    }

                    if (curDialog.getApplicationContext().getApplicationContextVersion().getVersion() > 1)
                        informServiceCentrePossible = true;
                    break;

                case SRIReaction.VAL_RETURN_SUCCESS_WITH_LMSI:
                    LMSI lmsi = mapProvider.getMAPParameterFactory().createLMSI(new byte[] { 11, 12, 13, 14 });
                    li = mapProvider.getMAPParameterFactory().createLocationInfoWithLMSI(networkNodeNumber, lmsi, null, false, null);
                    curDialog.addSendRoutingInfoForSMResponse(invokeId, imsi, li, null, null);

                    this.countSriResp++;
                    uData = this.createSriRespData(curDialog.getLocalDialogId(), imsi, li);
                    this.testerHost.sendNotif(SOURCE_NAME, "Sent: sriResp", uData, Level.DEBUG);

                    if (curDialog.getApplicationContext().getApplicationContextVersion().getVersion() > 1)
                        informServiceCentrePossible = true;
                    break;

                case SRIReaction.VAL_ERROR_ABSENT_SUBSCRIBER:
                    MAPErrorMessage mapErrorMessage = null;
                    switch (curDialog.getApplicationContext().getApplicationContextVersion()) {
                        case version1:
                            Boolean mwdSet = null;
                            if (this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getSRIInformServiceCenter().intValue() == SRIInformServiceCenter.MWD_mnrf
                                    || this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getSRIInformServiceCenter().intValue() == SRIInformServiceCenter.MWD_mcef_mnrf)
                                mwdSet = true;
                            mapErrorMessage = mapProvider.getMAPErrorMessageFactory().createMAPErrorMessageAbsentSubscriber(mwdSet);
                            break;
                        case version2:
                            mapErrorMessage = mapProvider.getMAPErrorMessageFactory().createMAPErrorMessageAbsentSubscriber(null, null);
                            informServiceCentrePossible = true;
                            break;
                        default:
                            mapErrorMessage = mapProvider.getMAPErrorMessageFactory().createMAPErrorMessageAbsentSubscriberSM(
                                    AbsentSubscriberDiagnosticSM.IMSIDetached, null, null);
                            informServiceCentrePossible = true;
                            break;
                    }

                    curDialog.sendErrorComponent(invokeId, mapErrorMessage);

                    this.countErrSent++;
                    uData = this.createErrorData(curDialog.getLocalDialogId(), (int) invokeId, mapErrorMessage);
                    this.testerHost.sendNotif(SOURCE_NAME, "Sent: errAbsSubs", uData, Level.DEBUG);
                    break;

                case SRIReaction.VAL_ERROR_CALL_BARRED:
                    mapErrorMessage = mapProvider.getMAPErrorMessageFactory().createMAPErrorMessageCallBarred(
                            (long) curDialog.getApplicationContext().getApplicationContextVersion().getVersion(), CallBarringCause.operatorBarring, null, null);
                    curDialog.sendErrorComponent(invokeId, mapErrorMessage);

                    this.countErrSent++;
                    uData = this.createErrorData(curDialog.getLocalDialogId(), (int) invokeId, mapErrorMessage);
                    this.testerHost.sendNotif(SOURCE_NAME, "Sent: errCallBarr", uData, Level.DEBUG);
                    break;

                case SRIReaction.VAL_ERROR_SYSTEM_FAILURE:
                    mapErrorMessage = mapProvider.getMAPErrorMessageFactory().createMAPErrorMessageSystemFailure(
                            (long) curDialog.getApplicationContext().getApplicationContextVersion().getVersion(), NetworkResource.hlr, null, null);
                    curDialog.sendErrorComponent(invokeId, mapErrorMessage);

                    this.countErrSent++;
                    uData = this.createErrorData(curDialog.getLocalDialogId(), (int) invokeId, mapErrorMessage);
                    this.testerHost.sendNotif(SOURCE_NAME, "Sent: errSysFail", uData, Level.DEBUG);
                    break;
            }

            if (informServiceCentrePossible) {
                MWStatus mwStatus = null;
                boolean scAddressNotIncluded = this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().isSRIScAddressNotIncluded();
                SRIInformServiceCenter sriInformServiceCenter = this.testerHost.getConfigurationData().getTestAttackClientConfigurationData()
                        .getSRIInformServiceCenter();

                if (this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().isReturn20PersDeliveryErrors()) {
                    int n = rnd.nextInt(5);
                    if (n == 0) {
                        n = rnd.nextInt(4);
                        sriInformServiceCenter = new SRIInformServiceCenter(n + 2);
                    } else {
                        sriInformServiceCenter = new SRIInformServiceCenter(SRIInformServiceCenter.MWD_NO);
                    }
                }

                switch (sriInformServiceCenter.intValue()) {
                    case SRIInformServiceCenter.MWD_NO:
                        break;
                    case SRIInformServiceCenter.MWD_mcef:
                        mwStatus = mapProvider.getMAPParameterFactory().createMWStatus(scAddressNotIncluded, false, true, false);
                        break;
                    case SRIInformServiceCenter.MWD_mnrf:
                        mwStatus = mapProvider.getMAPParameterFactory().createMWStatus(scAddressNotIncluded, true, false, false);
                        break;
                    case SRIInformServiceCenter.MWD_mcef_mnrf:
                        mwStatus = mapProvider.getMAPParameterFactory().createMWStatus(scAddressNotIncluded, true, true, false);
                        break;
                    case SRIInformServiceCenter.MWD_mnrg:
                        mwStatus = mapProvider.getMAPParameterFactory().createMWStatus(scAddressNotIncluded, false, false, true);
                        break;
                }
                if (mwStatus != null) {
                    curDialog.addInformServiceCentreRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, null, mwStatus, null, null, null);

                    this.countIscReq++;
                    uData = this.createIscReqData(curDialog.getLocalDialogId(), mwStatus);
                    this.testerHost.sendNotif(SOURCE_NAME, "Sent: iscReq", uData, Level.DEBUG);
                }
            }

            this.needSendClose = true;

        } catch (MAPException e) {
            this.testerHost.sendNotif(SOURCE_NAME, "Exception when invoking addSendRoutingInfoForSMResponse() : " + e.getMessage(), e, Level.ERROR);
        }
    }

    private String createSriData(SendRoutingInfoForSMRequest ind) {
        StringBuilder sb = new StringBuilder();
        sb.append("dialogId=");
        sb.append(ind.getMAPDialog().getLocalDialogId());
        sb.append(",\nsriReq=");
        sb.append(ind);

        sb.append(",\nRemoteAddress=");
        sb.append(ind.getMAPDialog().getRemoteAddress());
        sb.append(",\nLocalAddress=");
        sb.append(ind.getMAPDialog().getLocalAddress());

        return sb.toString();
    }

    private String createSriRespData(long dialogId, IMSI imsi, LocationInfoWithLMSI li) {
        StringBuilder sb = new StringBuilder();
        sb.append("dialogId=");
        sb.append(dialogId);
        sb.append(",\n imsi=");
        sb.append(imsi);
        sb.append(",\n locationInfo=");
        sb.append(li);
        sb.append(",\n");
        return sb.toString();
    }

    private String createIscReqData(long dialogId, MWStatus mwStatus) {
        StringBuilder sb = new StringBuilder();
        sb.append("dialogId=");
        sb.append(dialogId);
        sb.append(",\n mwStatus=");
        sb.append(mwStatus);
        sb.append(",\n");
        return sb.toString();
    }

    private String createErrorData(long dialogId, int invokeId, MAPErrorMessage mapErrorMessage) {
        StringBuilder sb = new StringBuilder();
        sb.append("dialogId=");
        sb.append(dialogId);
        sb.append(",\n invokeId=");
        sb.append(invokeId);
        sb.append(",\n mapErrorMessage=");
        sb.append(mapErrorMessage);
        sb.append(",\n");
        return sb.toString();
    }

    @Override
    public void onSendRoutingInfoForSMResponse(SendRoutingInfoForSMResponse sendRoutingInfoForSMRespInd) {
        this.sriResponse = sendRoutingInfoForSMRespInd;
    }

    public SendRoutingInfoForSMResponse getLastSRIForSMResponse() {
        return this.sriResponse;
    }

    public void clearLastSRIForSMResponse() {
        this.sriResponse = null;
    }

    public void performSendRoutingInfoForSM(String destIsdnNumber, String serviceCentreAddr) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();

        MAPApplicationContextVersion version = MAPApplicationContextVersion.version3;
        MAPApplicationContext context = MAPApplicationContext.getInstance(MAPApplicationContextName.shortMsgGatewayContext, version);

        ISDNAddressString msisdn = mapProvider.getMAPParameterFactory().createISDNAddressString(
                this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getAddressNature(),
                this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getNumberingPlan(), destIsdnNumber);
        AddressString serviceCentreAddress = mapProvider.getMAPParameterFactory().createAddressString(
                this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getAddressNature(),
                this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getNumberingPlan(), serviceCentreAddr);

        try {
            MAPDialogSms curDialog = mapProvider.getMAPServiceSms()
                    .createNewDialog(context,
                            this.mapMan.createOrigAddress(),
                            null,
                            this.mapMan.createDestAddress(),
                            null);

            curDialog.addSendRoutingInfoForSMRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, msisdn, true, serviceCentreAddress, null, false , null, null, null);
            curDialog.send();
        } catch(MAPException ex) {

        }
    }

    @Override
    public void onReportSMDeliveryStatusRequest(ReportSMDeliveryStatusRequest ind) {
        long invokeId = ind.getInvokeId();
        MAPDialogSms curDialog = ind.getMAPDialog();

        try {
            curDialog.addReportSMDeliveryStatusResponse(invokeId, ind.getMsisdn(), null);
            this.needSendClose = true;
        } catch (MAPException e) {
            System.out.println("Error when sending ReportSMDeliveryStatusRequest: " + e.toString());
        }
    }

    @Override
    public void onReportSMDeliveryStatusResponse(ReportSMDeliveryStatusResponse reportSMDeliveryStatusRespInd) {
    }

    public void performReportSMDeliveryStatus(ISDNAddressString msisdn) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPParameterFactory parameterFactory = mapProvider.getMAPParameterFactory();

        MAPApplicationContext applicationContext = MAPApplicationContext.getInstance(MAPApplicationContextName.shortMsgGatewayContext, MAPApplicationContextVersion.version3);
        try {
            MAPDialogSms curDialog = mapProvider.getMAPServiceSms().createNewDialog(applicationContext,
                    this.mapMan.createOrigAddress(),
                    null,
                    this.mapMan.createDestAddress(),
                    null);

            AddressString serviceCentreAddress = parameterFactory.createAddressString(
                    this.testerHost.getAttackSimulationOrganizer().getDefaultHlrAddress().getAddressNature(),
                    this.testerHost.getAttackSimulationOrganizer().getDefaultSmscAddress().getNumberingPlan(),
                    this.testerHost.getAttackSimulationOrganizer().getDefaultSmscAddress().getAddress());
            SMDeliveryOutcome smDeliveryOutcome = SMDeliveryOutcome.successfulTransfer;

            curDialog.addReportSMDeliveryStatusRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, msisdn, serviceCentreAddress, smDeliveryOutcome, 0, null, false, true, null, 0);
            curDialog.send();
        } catch (MAPException ex) {
            System.out.println("Error when sending RegisterSS Req: " + ex.toString());
        }
    }

    @Override
    public void onInformServiceCentreRequest(InformServiceCentreRequest informServiceCentreInd) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onAlertServiceCentreRequest(AlertServiceCentreRequest ind) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPDialogSms curDialog = ind.getMAPDialog();
        long invokeId = ind.getInvokeId();

        try {
            curDialog.addAlertServiceCentreResponse(invokeId);
            this.needSendClose = true;
        } catch (MAPException e) {
            this.testerHost.sendNotif(SOURCE_NAME, "Exception when invoking addAlertServiceCentreResponse() : " + e.getMessage(), e, Level.ERROR);
        }
    }

    @Override
    public void onAlertServiceCentreResponse(AlertServiceCentreResponse ind) {
        if (!isStarted)
            return;

        this.countAscResp++;

        MAPDialogSms curDialog = ind.getMAPDialog();
        long invokeId = curDialog.getLocalDialogId();
        currentRequestDef += "Rsvd ascResp;";
        this.testerHost.sendNotif(SOURCE_NAME, "Rcvd: ascResp", "", Level.DEBUG);
    }

    @Override
    public void onDialogRequest(MAPDialog dlg, AddressString arg1, AddressString arg2, MAPExtensionContainer arg3) {
        // refuse example
        // try {
        // dlg.refuse(Reason.invalidDestinationReference);
        // } catch (MAPException e) {
        // e.printStackTrace();
        // }
    }

    @Override
    public void onDialogDelimiter(MAPDialog mapDialog) {

        if (mapDialog.getApplicationContext().getApplicationContextName() == MAPApplicationContextName.shortMsgMTRelayContext
                || mapDialog.getApplicationContext().getApplicationContextName() == MAPApplicationContextName.shortMsgMORelayContext) {
            if (mapDialog.getUserObject() != null) {
                ResendMessageData md = (ResendMessageData) mapDialog.getUserObject();
                try {
                    MAPDialogSms dlg = (MAPDialogSms) mapDialog;

                    if (dlg.getApplicationContext().getApplicationContextVersion().getVersion() <= 2)
                        dlg.addForwardShortMessageRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, md.da, md.oa, md.si, false);
                    else
                        dlg.addMoForwardShortMessageRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, md.da, md.oa, md.si, null, null);
                    mapDialog.send();

                    String mtData = createMoData(mapDialog.getLocalDialogId(), md.destIsdnNumber, md.origIsdnNumber, md.serviceCentreAddr);
                    currentRequestDef += "Rcvd emptTCont;Sent moReq;";
                    this.countMoFsmReq++;
                    this.testerHost.sendNotif(SOURCE_NAME, "Rcvd: emptTCont", "", Level.DEBUG);
                    this.testerHost.sendNotif(SOURCE_NAME, "Sent: moReq: " + md.msg, mtData, Level.DEBUG);
                } catch (Exception e) {
                    this.testerHost.sendNotif(SOURCE_NAME, "Exception when invoking close() : " + e.getMessage(), e, Level.ERROR);
                    return;
                }
                mapDialog.setUserObject(null);
                return;
            }
        }

        try {
            if (needSendSend) {
                needSendSend = false;
                mapDialog.send();
                return;
            }
        } catch (Exception e) {
            this.testerHost.sendNotif(SOURCE_NAME, "Exception when invoking send() : " + e.getMessage(), e, Level.ERROR);
            return;
        }
        try {
            if (needSendClose) {
                needSendClose = false;
                mapDialog.close(false);
                return;
            }
        } catch (Exception e) {
            this.testerHost.sendNotif(SOURCE_NAME, "Exception when invoking close() : " + e.getMessage(), e, Level.ERROR);
            return;
        }

        if (mapDialog.getApplicationContext().getApplicationContextName() == MAPApplicationContextName.shortMsgMTRelayContext
                || mapDialog.getApplicationContext().getApplicationContextName() == MAPApplicationContextName.shortMsgMORelayContext) {
            // this is an empty first TC-BEGIN for MO SMS
            try {
                mapDialog.send();
                if (!this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().isOneNotificationFor100Dialogs()) {
                    // currentRequestDef += "Rcvd emptTBeg;Sent emptTCont;";
                    this.testerHost.sendNotif(SOURCE_NAME, "Rcvd: emptTBeg", "", Level.DEBUG);
                    this.testerHost.sendNotif(SOURCE_NAME, "Sent: emptTCont", "", Level.DEBUG);
                }
            } catch (Exception e) {
                this.testerHost.sendNotif(SOURCE_NAME, "Exception when invoking send() : " + e.getMessage(), e, Level.ERROR);
            }
            return;
        }
    }

    @Override
    public void onErrorComponent(MAPDialog dlg, Long invokeId, MAPErrorMessage msg) {
        super.onErrorComponent(dlg, invokeId, msg);

        // needSendClose = true;
    }

    @Override
    public void onRejectComponent(MAPDialog mapDialog, Long invokeId, Problem problem, boolean isLocalOriginated) {
        super.onRejectComponent(mapDialog, invokeId, problem, isLocalOriginated);
        if (isLocalOriginated)
            needSendClose = true;
    }

    public void performUpdateLocationRequest(IMSI imsi, ISDNAddressString mscNumber, ISDNAddressString vlrNumber, boolean attackerOriginated, int newLac) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();

        MAPApplicationContextVersion vers = MAPApplicationContextVersion.version3;
        MAPApplicationContextName acn = MAPApplicationContextName.networkLocUpContext;

        MAPApplicationContext mapApplicationContext = MAPApplicationContext.getInstance(acn, vers);
        MAPParameterFactory parameterFactory = mapProvider.getMAPParameterFactory();

        try{
            MAPDialogMobility curDialog = mapProvider.getMAPServiceMobility()
                    .createNewDialog(mapApplicationContext,
                            this.mapMan.createOrigAddress(),
                            null,
                            this.mapMan.createDestAddress(),
                            null);

            ArrayList<LocationArea> lac = new ArrayList<LocationArea>();
            lac.add(parameterFactory.createLocationArea(parameterFactory.createLAC(newLac)));
            PagingArea pagingArea = parameterFactory.createPagingArea(lac);

            if(attackerOriginated) {
                curDialog.addUpdateLocationRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, imsi, mscNumber, null, vlrNumber, null, null, null, false, false, null, null, pagingArea, false, false);
            } else {
                VLRCapability vlrCapability = parameterFactory.createVlrCapability(
                    parameterFactory.createSupportedCamelPhases(true, true, true, true),
                        null,
                        false,
                        ISTSupportIndicator.basicISTSupported,
                        parameterFactory.createSuperChargerInfo(true),
                        true,
                        parameterFactory.createSupportedLCSCapabilitySets(true, true, true, true, true),
                        parameterFactory.createOfferedCamel4CSIs(true, true, true, true, true, true, true),
                        parameterFactory.createSupportedRATTypes(true, true, true, true, true),
                        true,
                        true
                );

                curDialog.addUpdateLocationRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, imsi, mscNumber, null, vlrNumber, null, null, vlrCapability, true, false, null, null, pagingArea, true, false);
            }

            curDialog.send();
        } catch (MAPException ex) {
            System.out.println("Exception when sending UpdateLocationRequest :" + ex.toString());
        }
    }

    private VLRCapability getVLRCapability(MAPParameterFactory mapParameterFactory) {
        SupportedCamelPhases supportedCamelPhases = mapParameterFactory.createSupportedCamelPhases(true, true, true, true);
        MAPExtensionContainer mapExtensionContainer = null;
        boolean solsaSupportIndicator = false;
        ISTSupportIndicator istSupportIndicator = ISTSupportIndicator.basicISTSupported;
        SuperChargerInfo superChargerInfo = mapParameterFactory.createSuperChargerInfo(true);
        boolean longFtnSupported = false;
        SupportedLCSCapabilitySets supportedLCSCapabilitySets = mapParameterFactory.createSupportedLCSCapabilitySets(true, true, true, true, true);
        OfferedCamel4CSIs offeredCamel4CSIs = mapParameterFactory.createOfferedCamel4CSIs(true, true, true, true, true, true, true);
        SupportedRATTypes supportedRATTypes = mapParameterFactory.createSupportedRATTypes(true, true, true, true, true);
        boolean longGroupIDSupported = false;
        boolean mtRoamingForwardingSupported = true;

        return mapParameterFactory.createVlrCapability(supportedCamelPhases, mapExtensionContainer,
                solsaSupportIndicator, istSupportIndicator, superChargerInfo, longFtnSupported,
                supportedLCSCapabilitySets, offeredCamel4CSIs, supportedRATTypes, longGroupIDSupported,
                mtRoamingForwardingSupported);
    }

    @Override
    public void onUpdateLocationRequest(UpdateLocationRequest ind) {
        MAPDialogMobility curDialog = ind.getMAPDialog();
        long invokeId = ind.getInvokeId();
        AttackSimulationOrganizer organizer = this.testerHost.getAttackSimulationOrganizer();

        Subscriber subscriber = this.testerHost.getAttackSimulationOrganizer().getSubscriberManager().getSubscriber(ind.getImsi());

        if(subscriber != null) {
            MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
            MAPParameterFactory mapParameterFactory = this.mapMan.getMAPStack().getMAPProvider().getMAPParameterFactory();

            if(this.testerHost.hashCode() == organizer.getHlrAvlrA().hashCode()) { //New VLR is VLR_A
                organizer.getHlrAvlrB().getTestAttackServer().performCancelLocation(subscriber.getImsi());
                organizer.waitForCancelLocationResponse(organizer.getHlrAvlrB(), false);
                organizer.getHlrAvlrB().getTestAttackServer().clearLastCancelLocationResponse();

                organizer.getHlrAvlrA().getTestAttackClient().performActivateTraceMode(subscriber.getImsi());
                organizer.waitForActivateTraceModeResponse(organizer.getHlrAvlrA(), true);
                organizer.getHlrAvlrA().getTestAttackClient().clearLastActivateTraceModeResponse();

                organizer.getHlrAvlrA().getTestAttackClient().performInsertSubscriberData();
                organizer.waitForInsertSubscriberDataResponse(organizer.getHlrAvlrA(), true);
                organizer.getHlrAvlrA().getTestAttackClient().clearLastInsertSubscriberDataResponse();
            } else if(this.testerHost.hashCode() == organizer.getHlrBvlrA().hashCode()) { //New VLR is VLR_A
                organizer.getHlrBvlrA().getTestAttackClient().performActivateTraceMode(subscriber.getImsi());
                organizer.waitForActivateTraceModeResponse(organizer.getHlrBvlrA(), true);
                organizer.getHlrBvlrA().getTestAttackClient().clearLastActivateTraceModeResponse();

                organizer.getHlrBvlrA().getTestAttackClient().performInsertSubscriberData();
                organizer.waitForInsertSubscriberDataResponse(organizer.getHlrBvlrA(), true);
                organizer.getHlrBvlrA().getTestAttackClient().clearLastInsertSubscriberDataResponse();
            }

            ISDNAddressString newMscNumber = ind.getMscNumber();
            ISDNAddressString hlrNumber = subscriber.getCurrentHlrNumber();
            ISDNAddressString newVlrNumber = ind.getVlrNumber();

            subscriber.setCurrentMscNumber(newMscNumber);
            subscriber.setCurrentVlrNumber(newVlrNumber);

            try {
                int newLac, newCellID = 0;
                newLac = ind.getPagingArea().getLocationAreas().get(0).getLAC().getLac();

                switch(newLac) {
                    case AttackSimulationOrganizer.LAC_A_1:
                        newCellID = AttackSimulationOrganizer.CELLID_A_1;
                        break;
                    case AttackSimulationOrganizer.LAC_A_2:
                        newCellID = AttackSimulationOrganizer.CELLID_A_2;
                        break;
                    case AttackSimulationOrganizer.LAC_A_3:
                        newCellID = AttackSimulationOrganizer.CELLID_A_3;
                        break;
                    case AttackSimulationOrganizer.LAC_B_1:
                        newCellID = AttackSimulationOrganizer.CELLID_B_1;
                        break;
                    case AttackSimulationOrganizer.LAC_B_2:
                        newCellID = AttackSimulationOrganizer.CELLID_B_2;
                        break;
                    case AttackSimulationOrganizer.LAC_B_3:
                        newCellID = AttackSimulationOrganizer.CELLID_B_3;
                        break;
                    case AttackSimulationOrganizer.LAC_C_1:
                        newCellID = AttackSimulationOrganizer.CELLID_C_1;
                        break;
                }
                subscriber.setSubscriberInfo(organizer.getSubscriberManager().createNewSubscriberLocation(subscriber, newLac, newCellID));

                curDialog.addUpdateLocationResponse(invokeId, hlrNumber, null, false, true);
                this.needSendClose = true;
            } catch(MAPException e) {
                System.out.println("ERROR when sending UpdateLocationResponse: " + e.toString());
            }
        } else {
            System.out.println("ERROR in onUpdateLocationRequest.Could not find subscriber with IMSI: " + ind.getImsi().getData());
        }
    }

    @Override
    public void onUpdateLocationResponse(UpdateLocationResponse ind) {
        this.lastUpdateLocationResponse = ind;
    }

    public UpdateLocationResponse getLastUpdateLocationResponse() {
        return this.lastUpdateLocationResponse;
    }

    public void clearLastUpdateLocationResponse() {
        this.lastUpdateLocationResponse = null;
    }

    @Override
    public void onCancelLocationRequest(CancelLocationRequest request) {
        long invokeId = request.getInvokeId();
        MAPDialogMobility curDialog = request.getMAPDialog();

        try {
            curDialog.addCancelLocationResponse(invokeId, null);
            this.needSendClose = true;
        } catch (MAPException e) {
            System.out.println("Error when sending CancelLocation Resp" + e.toString());
        }
    }

    @Override
    public void onCancelLocationResponse(CancelLocationResponse response) {
        this.lastCancelLocationResponse = response;
    }

    public CancelLocationResponse getLastCancelLocationResponse() {
        return this.lastCancelLocationResponse;
    }

    public void clearLastCancelLocationResponse() {
        this.lastCancelLocationResponse = null;
    }

    @Override
    public void onSendIdentificationRequest(SendIdentificationRequest request) {

    }

    @Override
    public void onSendIdentificationResponse(SendIdentificationResponse response) {

    }

    @Override
    public void onUpdateGprsLocationRequest(UpdateGprsLocationRequest request) {

    }

    @Override
    public void onUpdateGprsLocationResponse(UpdateGprsLocationResponse response) {

    }

    @Override
    public void onPurgeMSRequest(PurgeMSRequest request) {
        long invokeId = request.getInvokeId();
        MAPDialogMobility curDialog = request.getMAPDialog();

        try {
            curDialog.addPurgeMSResponse(invokeId, false, false, null, false);
            this.needSendClose = true;
        } catch (MAPException e) {
            System.out.println("Error when sending PurgeMS Resp" + e.toString());
        }
    }

    @Override
    public void onPurgeMSResponse(PurgeMSResponse response) {

    }

    public void performPurgeMS(IMSI imsi, ISDNAddressString vlrNumber) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPParameterFactory parameterFactory = mapProvider.getMAPParameterFactory();

        Subscriber subscriber = this.testerHost.getAttackSimulationOrganizer().getSubscriberManager().getRandomSubscriber();

        MAPApplicationContext mapApplicationContext = MAPApplicationContext.getInstance(
                MAPApplicationContextName.msPurgingContext,
                MAPApplicationContextVersion.version3);

        try {
            MAPDialogMobility curDialog = mapProvider.getMAPServiceMobility().createNewDialog(mapApplicationContext,
                    this.mapMan.createOrigAddress(),
                    null,
                    this.mapMan.createDestAddress(),
                    null);

            curDialog.addPurgeMSRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, imsi, vlrNumber, null, null);
            curDialog.send();
        } catch (MAPException e) {
            System.out.println("Error performing PurgeMS: " + e.toString());
        }
    }

    @Override
    public void onSendAuthenticationInfoRequest(SendAuthenticationInfoRequest ind) {

    }

    @Override
    public void onSendAuthenticationInfoResponse(SendAuthenticationInfoResponse ind) {

    }

    @Override
    public void onAuthenticationFailureReportRequest(AuthenticationFailureReportRequest ind) {

    }

    @Override
    public void onAuthenticationFailureReportResponse(AuthenticationFailureReportResponse ind) {

    }

    @Override
    public void onResetRequest(ResetRequest ind) {

    }

    @Override
    public void onForwardCheckSSIndicationRequest(ForwardCheckSSIndicationRequest ind) {
        long invokeId = ind.getInvokeId();
        MAPDialogMobility curDialog = ind.getMAPDialog();
    }

    @Override
    public void onRestoreDataRequest(RestoreDataRequest ind) {
        long invokeId = ind.getInvokeId();
        MAPDialogMobility curDialog = ind.getMAPDialog();
        AttackSimulationOrganizer organizer = this.testerHost.getAttackSimulationOrganizer();

        Subscriber subscriber = this.testerHost.getAttackSimulationOrganizer().getSubscriberManager().getSubscriber(ind.getImsi());

        if(subscriber != null) {
            try {
                if(this.testerHost.hashCode() == organizer.getHlrAvlrA().hashCode()) {
                    organizer.getHlrAvlrA().getTestAttackClient().performInsertSubscriberData();
                    organizer.waitForInsertSubscriberDataResponse(organizer.getHlrAvlrA(), true);
                    organizer.getHlrAvlrA().getTestAttackClient().clearLastInsertSubscriberDataResponse();
                } else if (this.testerHost.hashCode() == organizer.getHlrBvlrA().hashCode()) {
                    organizer.getHlrBvlrA().getTestAttackClient().performInsertSubscriberData();
                    organizer.waitForInsertSubscriberDataResponse(organizer.getHlrBvlrA(), true);
                    organizer.getHlrBvlrA().getTestAttackClient().clearLastInsertSubscriberDataResponse();
                }

                curDialog.addRestoreDataResponse(invokeId, subscriber.getCurrentHlrNumber(), false, null);
                this.needSendClose = true;
            } catch (MAPException e) {
                System.out.println("Error when sending RestoreData Resp: " + e.toString());
            }
        } else {
            System.out.println("Error: Could not find subscriber with IMSI: " + ind.getImsi());
        }
    }

    @Override
    public void onRestoreDataResponse(RestoreDataResponse ind) {

    }

    public void performRestoreData(IMSI imsi) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPParameterFactory parameterFactory = mapProvider.getMAPParameterFactory();

        MAPApplicationContext applicationContext = MAPApplicationContext.getInstance(MAPApplicationContextName.networkLocUpContext, MAPApplicationContextVersion.version3);
        try {
            MAPDialogMobility curDialog = mapProvider.getMAPServiceMobility().createNewDialog(applicationContext,
                    this.mapMan.createOrigAddress(),
                    null,
                    this.mapMan.createDestAddress(),
                    null);

            curDialog.addRestoreDataRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, imsi, null, null, null, false);
            curDialog.send();
        } catch (MAPException ex) {
            System.out.println("Error when sending RestoreData Req: " + ex.toString());
        }
    }

    @Override
    public void onAnyTimeInterrogationRequest(AnyTimeInterrogationRequest request) {

    }

    @Override
    public void onAnyTimeInterrogationResponse(AnyTimeInterrogationResponse response) {

    }

    public void performATI(String msisdn) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPApplicationContextVersion version = MAPApplicationContextVersion.version3;
        MAPApplicationContextName name = MAPApplicationContextName.anyTimeEnquiryContext;

        MAPApplicationContext context = MAPApplicationContext.getInstance(name, version);

        try {
            MAPDialogMobility curDialog = mapProvider.getMAPServiceMobility().createNewDialog(
                    context,
                    this.mapMan.createOrigAddress(),
                    null,
                    this.mapMan.createDestAddress(),
                    null);

            AddressNature addressNature = this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getAddressNature();
            NumberingPlan numberingPlan = this.testerHost.getConfigurationData().getTestAttackClientConfigurationData().getNumberingPlan();

            SubscriberIdentity subscriberIdentity = mapProvider.getMAPParameterFactory().createSubscriberIdentity(
                    mapProvider.getMAPParameterFactory().createISDNAddressString(addressNature, numberingPlan, msisdn));
            RequestedInfo requestedInfo = mapProvider.getMAPParameterFactory().createRequestedInfo(
                    true, true, null, true, null, true, true, true);
            ISDNAddressString gsmSCFAddress = mapProvider.getMAPParameterFactory().createISDNAddressString(addressNature,
                    numberingPlan, this.testerHost.getConfigurationData().getSccpConfigurationData().getCallingPartyAddressDigits());
            MAPExtensionContainer mapExtensionContainer = null;

            curDialog.addAnyTimeInterrogationRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, subscriberIdentity, requestedInfo, gsmSCFAddress, mapExtensionContainer);
            curDialog.send();
        } catch (MAPException ex) {
            System.out.println("Exception when sending AnyTimeInterrogationRequest: " + ex.toString());
        }
    }

    public AnyTimeInterrogationResponse getLastAtiResponse() {
        return this.atiResponse;
    }

    public void clearLastAtiResponse() {
        this.atiResponse = null;
    }

    public void performProvideSubscriberInfoRequest(IMSI imsi) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPApplicationContextVersion acv = MAPApplicationContextVersion.version3;
        MAPApplicationContextName acn = MAPApplicationContextName.subscriberInfoEnquiryContext;

        MAPApplicationContext mapAppContext = MAPApplicationContext.getInstance(acn, acv);

        try {
            MAPDialogMobility curDialog = mapProvider.getMAPServiceMobility().createNewDialog(mapAppContext,
                    this.mapMan.createOrigAddress(),
                    null,
                    this.mapMan.createDestAddress(),
                    null);

            LMSI lmsi = mapProvider.getMAPParameterFactory().createLMSI(new byte[] { 11, 12, 13, 14 });
            RequestedInfo requestedInfo = new RequestedInfoImpl(true, true, null, true, null, true, true, true);
            MAPExtensionContainer mapExtensionContainer = null;
            EMLPPPriority emlppPriority = EMLPPPriority.priorityLevel0;

            if(curDialog == null)
                System.out.println("ERROR: curDialog is null");
            else {
                curDialog.addProvideSubscriberInfoRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, imsi, lmsi, requestedInfo, mapExtensionContainer, emlppPriority);
                curDialog.send();
            }
        } catch (MAPException ex) {
            System.out.println("Exception when sending ProvideSubscriberInfoRequest: " + ex.toString());
        }
    }

    @Override
    public void onProvideSubscriberInfoRequest(ProvideSubscriberInfoRequest request) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPParameterFactory mapParameterFactory = mapProvider.getMAPParameterFactory();
        MAPDialogMobility curDialog = request.getMAPDialog();
        long invokeId = request.getInvokeId();
        IMSI imsi = request.getImsi();

        Subscriber subscriber = this.testerHost.getAttackSimulationOrganizer().getSubscriberManager().getSubscriber(imsi);

        if(subscriber != null) {
            try {
                curDialog.addProvideSubscriberInfoResponse(invokeId, subscriber.getSubscriberInfo(), null);
                this.needSendClose = true;
            } catch (MAPException ex) {
                System.out.println("Exception when sending ProvideSubscriberInfoRequestRes: " + ex.toString());
            }
        } else {
            System.out.println("Could not find subscriber with IMSI: " + imsi.getData());
        }
    }

    @Override
    public void onProvideSubscriberInfoResponse(ProvideSubscriberInfoResponse response) {
        this.setPsiResponse(response);
    }

    public void setPsiResponse(ProvideSubscriberInfoResponse psiResponse) {
        this.psiResponse = psiResponse;
    }

    public ProvideSubscriberInfoResponse getLastPsiResponse() {
        return this.psiResponse;
    }

    public void clearLastPsiResponse() {
        this.psiResponse = null;
    }

    @Override
    public void onInsertSubscriberDataRequest(InsertSubscriberDataRequest request) {
        long invokeId = request.getInvokeId();
        MAPDialogMobility curDialog = request.getMAPDialog();

        try {
            curDialog.addInsertSubscriberDataResponse(invokeId, null, null, null, null, null);
            this.needSendClose = true;
        } catch (MAPException e) {
            System.out.println("Error when sending InsertSubscriberData Resp: " + e.toString());
        }
    }

    @Override
    public void onInsertSubscriberDataResponse(InsertSubscriberDataResponse request) {
        this.lastInsertSubscriberDataResponse = request;
    }

    public InsertSubscriberDataResponse getLastInsertSubscriberDataResponse() {
        return this.lastInsertSubscriberDataResponse;
    }

    public void clearLastInsertSubscriberDataResponse() {
        this.lastInsertSubscriberDataResponse = null;
    }

    public void performInsertSubscriberData() {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();

        MAPApplicationContext applicationContext = MAPApplicationContext.getInstance(MAPApplicationContextName.subscriberDataMngtContext, MAPApplicationContextVersion.version3);

        try {
            MAPDialogMobility curDialog =  mapProvider.getMAPServiceMobility().createNewDialog(applicationContext,
                    this.mapMan.createOrigAddress(),
                    null,
                    this.mapMan.createDestAddress(),
                    null);
            curDialog.addInsertSubscriberDataRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, null, null, null, null, null, null, null, null, false, null, null, null, null);
            curDialog.send();
        } catch (MAPException e) {
            System.out.println("Error when sending InsertSubscriberData Req: " + e.toString());
        }
    }

    @Override
    public void onDeleteSubscriberDataRequest(DeleteSubscriberDataRequest request) {

    }

    @Override
    public void onDeleteSubscriberDataResponse(DeleteSubscriberDataResponse request) {

    }

    public void performDeleteSubscriberData(IMSI imsi) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPParameterFactory parameterFactory = mapProvider.getMAPParameterFactory();

        MAPApplicationContext applicationContext = MAPApplicationContext.getInstance(MAPApplicationContextName.subscriberDataMngtContext, MAPApplicationContextVersion.version3);
        try {
            MAPDialogMobility curDialog = mapProvider.getMAPServiceMobility().createNewDialog(applicationContext,
                    this.mapMan.createOrigAddress(),
                    null,
                    this.mapMan.createDestAddress(),
                    null);

            curDialog.addDeleteSubscriberDataRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, imsi, null, null, false, null, false, false, false, null, null, false, null, false, false, null, false, false, null, false, false);
            curDialog.send();
        } catch (MAPException ex) {
            System.out.println("Error when sending DeleteSubscriberData Req: " + ex.toString());
        }
    }

    @Override
    public void onCheckImeiRequest(CheckImeiRequest request) {
        long invokeId = request.getInvokeId();
        MAPDialogMobility curDialog = request.getMAPDialog();
        try {
            curDialog.addCheckImeiResponse(invokeId, EquipmentStatus.whiteListed, null, null);
            this.needSendClose = true;
        } catch (MAPException e) {
            System.out.println("Error when sending CheckImei Resp: " + e.toString());
        }
    }

    @Override
    public void onCheckImeiResponse(CheckImeiResponse response) {

    }

    @Override
    public void onActivateTraceModeRequest_Mobility(ActivateTraceModeRequest_Mobility ind) {
        long invokeId = ind.getInvokeId();
        MAPDialogMobility curDialog = ind.getMAPDialog();

        try {
            curDialog.addActivateTraceModeResponse(invokeId, null, true);
            this.needSendClose = true;
        } catch (MAPException e) {
            System.out.println("Error when sending ActivateTraceMode Resp: " + e.toString());
        }
    }

    @Override
    public void onActivateTraceModeResponse_Mobility(ActivateTraceModeResponse_Mobility ind) {
        this.lastActivateTraceModeResponse = ind;
    }

    public void performActivateTraceMode(IMSI imsi) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPParameterFactory parameterFactory = mapProvider.getMAPParameterFactory();

        MAPApplicationContext applicationContext = MAPApplicationContext.getInstance(MAPApplicationContextName.tracingContext, MAPApplicationContextVersion.version3);
        try {
            MAPDialogMobility curDialog = mapProvider.getMAPServiceMobility().createNewDialog(applicationContext,
                    this.mapMan.createOrigAddress(),
                    null,
                    this.mapMan.createDestAddress(),
                    null);

            TraceReference traceReference = parameterFactory.createTraceReference(new byte[]{01, 02});
            TraceType traceType = parameterFactory.createTraceType(HlrRecordType.Basic,
                    TraceTypeInvokingEvent.InvokingEvent_0, false);

            curDialog.addActivateTraceModeRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, imsi, traceReference, traceType, null, null, null, null, null, null, null, null, null);
            curDialog.send();
        } catch (MAPException ex) {
            System.out.println("Error when sending ActivateTraceMode Req: " + ex.toString());
        }
    }

    public ActivateTraceModeResponse_Mobility getLastActivateTraceModeResponse() {
        return this.lastActivateTraceModeResponse;
    }

    public void clearLastActivateTraceModeResponse() {
        this.lastActivateTraceModeResponse = null;
    }

    public void performActivateTraceMode_Mobility(IMSI imsi) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPParameterFactory parameterFactory = mapProvider.getMAPParameterFactory();

        MAPApplicationContext applicationContext = MAPApplicationContext.getInstance(MAPApplicationContextName.tracingContext, MAPApplicationContextVersion.version3);
        try {
            MAPDialogMobility curDialog = mapProvider.getMAPServiceMobility().createNewDialog(applicationContext,
                    this.mapMan.createOrigAddress(),
                    null,
                    this.mapMan.createDestAddress(),
                    null);

            TraceReference traceReference = parameterFactory.createTraceReference(new byte[]{1,2});
            TraceType traceType = parameterFactory.createTraceType(0);

            curDialog.addActivateTraceModeRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, imsi, traceReference, traceType, null, null, null, null, null, null,
                    null, null, null);
            curDialog.send();
        } catch (MAPException ex) {
            System.out.println("Error when sending ActivateTraceMode_Mobility Req: " + ex.toString());
        }
    }

    @Override
    public void onSendRoutingInformationRequest(SendRoutingInformationRequest request) {

    }

    @Override
    public void onSendRoutingInformationResponse(SendRoutingInformationResponse response) {
        this.lastSendRoutingInfoResponse = response;
    }

    public SendRoutingInformationResponse getLastSendRoutingInfoResponse() {
        return this.lastSendRoutingInfoResponse;
    }

    public void clearLastSendRoutingInformation() {
        this.lastSendRoutingInfoResponse = null;
    }

    public void performSendRoutingInformation(ISDNAddressString msisdn) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPParameterFactory parameterFactory = mapProvider.getMAPParameterFactory();

        MAPApplicationContext applicationContext = MAPApplicationContext.getInstance(MAPApplicationContextName.locationInfoRetrievalContext, MAPApplicationContextVersion.version3);
        try {
            MAPDialogCallHandling curDialog = mapProvider.getMAPServiceCallHandling().createNewDialog(applicationContext,
                    this.mapMan.createOrigAddress(),
                    null,
                    this.mapMan.createDestAddress(),
                    null);

            InterrogationType interrogationType = InterrogationType.basicCall;
            ISDNAddressString gsmcAddress = this.testerHost.getAttackSimulationOrganizer().getDefaultMscAddress();

            curDialog.addSendRoutingInformationRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, msisdn, null, 0, interrogationType, false, 0, gsmcAddress, null, null,
                    null, null, null, false, null, null, false, 0, null, null, false, null, false, false, false, false, null, null,
                    null, false, null);
            curDialog.send();
        } catch (MAPException ex) {
            System.out.println("Error when sending SendRoutingInformation Req: " + ex.toString());
        }
    }

    @Override
    public void onProvideRoamingNumberRequest(ProvideRoamingNumberRequest request) {
        long invokeId = request.getInvokeId();
        MAPDialogCallHandling curDialog = request.getMAPDialog();
        ISDNAddressString roamingNumber = this.mapMan.getMAPStack().getMAPProvider().getMAPParameterFactory()
                .createISDNAddressString(
                        AddressNature.international_number,
                        NumberingPlan.ISDN,
                        "9999999999");

        try {
            curDialog.addProvideRoamingNumberResponse(invokeId, roamingNumber, null, false, null);
            this.needSendClose = true;
        } catch (MAPException e) {
            System.out.println("Error when sending ProvideRoamingNumber Resp: " + e.toString());
        }
    }

    @Override
    public void onProvideRoamingNumberResponse(ProvideRoamingNumberResponse response) {
        this.lastProvideRoamingNumberResponse = response;
    }

    @Override
    public void onIstCommandRequest(IstCommandRequest request) {
        System.err.println("Warning! Placeholded method used");

    }

    @Override
    public void onIstCommandResponse(IstCommandResponse response) {
        System.err.println("Warning! Placeholded method used");

    }

    public ProvideRoamingNumberResponse getLastProvideRoamingNumberResponse() {
        return this.lastProvideRoamingNumberResponse;
    }

    public void clearLastProvideRoamingNumberResponse() {
        this.lastProvideRoamingNumberResponse = null;
    }

    public void performProvideRoamingNumber(IMSI imsi, ISDNAddressString mscNumber) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPParameterFactory parameterFactory = mapProvider.getMAPParameterFactory();

        MAPApplicationContext applicationContext = MAPApplicationContext.getInstance(MAPApplicationContextName.roamingNumberEnquiryContext, MAPApplicationContextVersion.version3);
        try {
            MAPDialogCallHandling curDialog = mapProvider.getMAPServiceCallHandling().createNewDialog(applicationContext,
                    this.mapMan.createOrigAddress(),
                    null,
                    this.mapMan.createDestAddress(),
                    null);

            curDialog.addProvideRoamingNumberRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, imsi, mscNumber, null, null, null, null, false, null, null, false,
                    null, null, false, null, null, false, false, false, false, null, false, null, null, false, null);
            curDialog.send();
        } catch (MAPException ex) {
            System.out.println("Error when sending ProvideRoamingNumber Req: " + ex.toString());
        }
    }

    @Override
    public void onActivateTraceModeRequest_Oam(ActivateTraceModeRequest_Oam ind) {

    }

    @Override
    public void onActivateTraceModeResponse_Oam(ActivateTraceModeResponse_Oam ind) {

    }

    public void performActivateTraceMode_Oam(IMSI imsi) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPParameterFactory parameterFactory = mapProvider.getMAPParameterFactory();

        MAPApplicationContext applicationContext = MAPApplicationContext.getInstance(MAPApplicationContextName.tracingContext, MAPApplicationContextVersion.version3);
        try {
            MAPDialogOam curDialog = mapProvider.getMAPServiceOam().createNewDialog(applicationContext,
                    this.mapMan.createOrigAddress(),
                    null,
                    this.mapMan.createDestAddress(),
                    null);

            TraceReference traceReference = parameterFactory.createTraceReference(new byte[]{1,2});
            TraceType traceType = parameterFactory.createTraceType(0);

            curDialog.addActivateTraceModeRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, imsi, traceReference, traceType, null, null, null, null, null, null,
                    null, null, null);
            curDialog.send();
        } catch (MAPException ex) {
            System.out.println("Error when sending ActivateTraceMode_Oam Req: " + ex.toString());
        }
    }

    @Override
    public void onSendImsiRequest(SendImsiRequest ind) {
        long invokeId = ind.getInvokeId();
        MAPDialogOam curDialog = ind.getMAPDialog();

        Subscriber subscriber = this.testerHost.getAttackSimulationOrganizer().getSubscriberManager().getSubscriber(ind.getMsisdn());

        if (subscriber != null) {
            try {
                curDialog.addSendImsiResponse(invokeId, subscriber.getImsi());
                this.needSendClose = true;
            } catch (MAPException e) {
                System.out.println("Error when sending SendImsi Resp: " + e.toString());
            }
        } else {
            System.out.println("Error: could not find subscriber with MSISDN: " + ind.getMsisdn());
        }
    }

    @Override
    public void onSendImsiResponse(SendImsiResponse ind) {

    }

    @Override
    public void onRegisterSSRequest(RegisterSSRequest request) {
        long invokeId = request.getInvokeId();
        MAPDialogSupplementary curDialog = request.getMAPDialog();

        try {
            curDialog.addRegisterSSResponse(invokeId, null);
            this.needSendClose = true;
        } catch (MAPException e) {
            System.out.println("Error when sending RegisterSS Resp: " + e.toString());
        }
    }

    @Override
    public void onRegisterSSResponse(RegisterSSResponse response) {
        this.lastRegisterSSResponse = response;
    }

    public RegisterSSResponse getLastRegisterSSResponse() {
        return this.lastRegisterSSResponse;
    }

    public void clearLastRegisterSSResponse() {
        this.lastRegisterSSResponse = null;
    }

    public void performRegisterSS(ISDNAddressString msisdn) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPParameterFactory parameterFactory = mapProvider.getMAPParameterFactory();

        MAPApplicationContext applicationContext = MAPApplicationContext.getInstance(MAPApplicationContextName.networkFunctionalSsContext, MAPApplicationContextVersion.version2);
        try {
            MAPDialogSupplementary curDialog = mapProvider.getMAPServiceSupplementary().createNewDialog(applicationContext,
                    this.mapMan.createOrigAddress(),
                    this.mapMan.createOrigReference(),
                    this.mapMan.createDestAddress(),
                    this.mapMan.createDestReference());

            SSCode ssCode = parameterFactory.createSSCode(SupplementaryCodeValue.universal);

            BasicServiceCode basicServiceCode = parameterFactory.createBasicServiceCode(
                    parameterFactory.createTeleserviceCode(TeleserviceCodeValue.allTeleservices));

            curDialog.addRegisterSSRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, ssCode, basicServiceCode, msisdn, null, 0, null, null, null);
            curDialog.send();
        } catch (MAPException ex) {
            System.out.println("Error when sending RegisterSS Req: " + ex.toString());
        }
    }

    @Override
    public void onEraseSSRequest(EraseSSRequest request) {
        long invokeId = request.getInvokeId();
        MAPDialogSupplementary curDialog = request.getMAPDialog();
        AttackSimulationOrganizer organizer = this.testerHost.getAttackSimulationOrganizer();

        try {
            curDialog.addEraseSSResponse(invokeId, null);
            this.needSendClose = true;
        } catch (MAPException e) {
            System.out.println("Error when sending EraseSS Resp: " + e.toString());
        }
    }

    @Override
    public void onEraseSSResponse(EraseSSResponse response) {
        this.lastEraseSSResponse = response;
    }

    public EraseSSResponse getLastEraseSSResponse() {
        return this.lastEraseSSResponse;
    }

    public void clearLastEraseSSResponse() {
        this.lastEraseSSResponse = null;
    }

    public void performEraseSS() {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPParameterFactory parameterFactory = mapProvider.getMAPParameterFactory();

        MAPApplicationContext applicationContext = MAPApplicationContext.getInstance(MAPApplicationContextName.networkFunctionalSsContext, MAPApplicationContextVersion.version2);
        try {
            MAPDialogSupplementary curDialog = mapProvider.getMAPServiceSupplementary().createNewDialog(applicationContext,
                    this.mapMan.createOrigAddress(),
                    this.mapMan.createOrigReference(),
                    this.mapMan.createDestAddress(),
                    this.mapMan.createDestReference());

            SSForBSCode ssForBSCode = parameterFactory.createSSForBSCode(parameterFactory.createSSCode(SupplementaryCodeValue.universal),
                    parameterFactory.createBasicServiceCode(parameterFactory.createTeleserviceCode(TeleserviceCodeValue.allTeleservices)),
                    false);

            curDialog.addEraseSSRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, ssForBSCode);
            curDialog.send();
        } catch (MAPException ex) {
            System.out.println("Error when sending EraseSS Req: " + ex.toString());
        }
    }

    @Override
    public void onActivateSSRequest(ActivateSSRequest request) {

    }

    @Override
    public void onActivateSSResponse(ActivateSSResponse response) {

    }

    public void performActivateSS() {

    }

    @Override
    public void onDeactivateSSRequest(DeactivateSSRequest request) {

    }

    @Override
    public void onDeactivateSSResponse(DeactivateSSResponse response) {

    }

    public void performDeactivateSS() {

    }

    @Override
    public void onInterrogateSSRequest(InterrogateSSRequest request) {

    }

    @Override
    public void onInterrogateSSResponse(InterrogateSSResponse response) {

    }

    public void performInterrogateSS(boolean forwardToHLR) {

    }

    @Override
    public void onGetPasswordRequest(GetPasswordRequest request) {

    }

    @Override
    public void onGetPasswordResponse(GetPasswordResponse response) {

    }

    @Override
    public void onRegisterPasswordRequest(RegisterPasswordRequest request) {

    }

    @Override
    public void onRegisterPasswordResponse(RegisterPasswordResponse response) {

    }

    public void performRegisterPassword() {

    }

    @Override
    public void onProcessUnstructuredSSRequest(ProcessUnstructuredSSRequest procUnstrReqInd) {

    }

    @Override
    public void onProcessUnstructuredSSResponse(ProcessUnstructuredSSResponse procUnstrResInd) {

    }

    @Override
    public void onUnstructuredSSRequest(UnstructuredSSRequest unstrReqInd) {

    }

    @Override
    public void onUnstructuredSSResponse(UnstructuredSSResponse unstrResInd) {

    }

    @Override
    public void onUnstructuredSSNotifyRequest(UnstructuredSSNotifyRequest unstrNotifyInd) {

    }

    @Override
    public void onUnstructuredSSNotifyResponse(UnstructuredSSNotifyResponse unstrNotifyInd) {

    }

    public void performCancelLocation(IMSI imsi) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPApplicationContext applicationContext = MAPApplicationContext.getInstance(
                MAPApplicationContextName.locationCancellationContext,
                MAPApplicationContextVersion.version3);

        try {
            MAPDialogMobility curDialog = mapProvider.getMAPServiceMobility().createNewDialog(
                    applicationContext,
                    this.mapMan.createOrigAddress(),
                    null,
                    this.mapMan.createDestAddress(),
                    null);

            curDialog.addCancelLocationRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, imsi, null, null, null, null, false, false, null, null, null);
            curDialog.send();
        } catch(MAPException e) {
            System.out.println("Error when sending CancelLocation Req: " + e.toString());
        }
    }

    public void performIsupIAM() {
        //ISUPStack isupStack = this.testerHost.getIsupMan().getIsupStack();
        //ISUPProvider isupProvider = isupStack.getIsupProvider();

        //try {
        //    CircuitIdentificationCode cic = isupProvider.getParameterFactory().createCircuitIdentificationCode();
        //    cic.setCIC(1);

        //    CalledPartyNumber cpn = isupProvider.getParameterFactory().createCalledPartyNumber();
        //    cpn.setInternalNetworkNumberIndicator(CalledPartyNumber._INN_ROUTING_ALLOWED);
        //    cpn.setNumberingPlanIndicator(CalledPartyNumber._NPI_ISDN);
        //    cpn.setAddress("82828282");
        //    cpn.setNatureOfAddresIndicator(CalledPartyNumber._NAI_INTERNATIONAL_NUMBER);

        //    NatureOfConnectionIndicators noci = isupProvider.getParameterFactory().createNatureOfConnectionIndicators();
        //    noci.setContinuityCheckIndicator(NatureOfConnectionIndicators._CCI_NOT_REQUIRED);
        //    noci.setEchoControlDeviceIndicator(true);
        //    noci.setSatelliteIndicator(NatureOfConnectionIndicators._SI_NO_SATELLITE);

        //    ForwardCallIndicators fci = isupProvider.getParameterFactory().createForwardCallIndicators();
        //    fci.setEndToEndInformationIndicator(false);
        //    fci.setEndToEndMethodIndicator(ForwardCallIndicators._ETEMI_NOMETHODAVAILABLE);
        //    fci.setInterworkingIndicator(false);
        //    fci.setIsdnAccessIndicator(true);
        //    fci.setIsdnUserPartIndicator(true);
        //    fci.setNationalCallIdentificator(false);
        //    fci.setSccpMethodIndicator(ForwardCallIndicators._SCCP_MI_NOINDICATION);

        //    CallingPartyCategory cpc = isupProvider.getParameterFactory().createCallingPartyCategory();
        //    cpc.setCallingPartyCategory(CallingPartyCategory._ORDINARY_SUBSCRIBER);

        //    TransmissionMediumRequirement tmr = isupProvider.getParameterFactory().createTransmissionMediumRequirement();
        //    tmr.setTransimissionMediumRequirement(TransmissionMediumRequirement._MEDIUM_64_KBIT_UNRESTRICTED);

        //    InitialAddressMessage msg = isupProvider.getMessageFactory().createIAM();
        //    msg.setCircuitIdentificationCode(isupProvider.getParameterFactory().createCircuitIdentificationCode());
        //    msg.setSls(1);
        //    msg.setCalledPartyNumber(cpn);
        //    msg.setNatureOfConnectionIndicators(noci);
        //    msg.setForwardCallIndicators(fci);
        //    msg.setCallingPartCategory(cpc);
        //    msg.setTransmissionMediumRequirement(tmr);

        //    isupProvider.sendMessage(msg, this.testerHost.getIsupMan().getDpc());
        //} catch(IOException ex) {
        //    System.out.println("Error when sending ISUP IAM: " + ex.toString());
        //} catch(ParameterException ex) {
        //    System.out.println("Error when sending ISUP IAM: " + ex.toString());
        //}
    }

    @Override
    public void onEvent(ISUPEvent event) {
        System.out.println("--------------GOT ISUP MESSAGE");
        System.out.println(event.getMessage().getMessageType().getMessageName().toString());
    }

    @Override
    public void onTimeout(ISUPTimeoutEvent event) {

    }

    @Override
    public void onSendRoutingInfoForGprsRequest(SendRoutingInfoForGprsRequest request) {

    }

    @Override
    public void onSendRoutingInfoForGprsResponse(SendRoutingInfoForGprsResponse response) {

    }

    public void performSendRoutingInfoForGPRS(IMSI imsi, ISDNAddressString ggsnNumber) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();
        MAPApplicationContext applicationContext = MAPApplicationContext.getInstance(
                MAPApplicationContextName.gprsLocationInfoRetrievalContext,
                MAPApplicationContextVersion.version4);

        try {
            MAPDialogPdpContextActivation curDialog = mapProvider.getMAPServicePdpContextActivation().createNewDialog(
                    applicationContext,
                    this.mapMan.createOrigAddress(),
                    null,
                    this.mapMan.createDestAddress(),
                    null);

            curDialog.addSendRoutingInfoForGprsRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, imsi, null, ggsnNumber, null);
            curDialog.send();
        } catch(MAPException e) {
            System.out.println("Error when sending SendRoutingInfoForGPRS Req: " + e.toString());
        }
    }

    private class ResendMessageData {
        public SM_RP_DA da;
        public SM_RP_OA oa;
        public SmsSignalInfo si;
        public String msg;
        public String destIsdnNumber;
        public String origIsdnNumber;
        public String serviceCentreAddr;
    }

    @Override
    public void onReadyForSMRequest(ReadyForSMRequest request) {
        long invokeId = request.getInvokeId();
        MAPDialogSms curDialog = request.getMAPDialog();

        try {
            curDialog.addReadyForSMResponse(invokeId, null);
            this.needSendClose = true;
        } catch (MAPException e) {
            System.out.println("Error when sending ReadyForSM Resp: " + e.toString());
        }
    }

    @Override
    public void onReadyForSMResponse(ReadyForSMResponse response) {

    }

    public void performReadyForSM(IMSI imsi) {
        MAPProvider mapProvider = this.mapMan.getMAPStack().getMAPProvider();

        MAPApplicationContext applicationContext = MAPApplicationContext.getInstance(MAPApplicationContextName.mwdMngtContext, MAPApplicationContextVersion.version3);
        try {
            MAPDialogSms curDialog = mapProvider.getMAPServiceSms().createNewDialog(applicationContext,
                    this.mapMan.createOrigAddress(),
                    null,
                    this.mapMan.createDestAddress(),
                    null);

            curDialog.addReadyForSMRequest(AttackSimulationOrganizer.TCAP_TIMEOUT, imsi, AlertReason.msPresent, true, null, false);
            curDialog.send();
        } catch (MAPException ex) {
            System.out.println("Error when sending ReadyForSM Req: " + ex.toString());
        }
    }

    @Override
    public void onNoteSubscriberPresentRequest(NoteSubscriberPresentRequest request) {

    }

}
