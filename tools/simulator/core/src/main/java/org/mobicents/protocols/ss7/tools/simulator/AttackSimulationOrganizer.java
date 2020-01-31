package org.mobicents.protocols.ss7.tools.simulator;

import org.mobicents.protocols.ss7.map.MAPParameterFactoryImpl;
import org.mobicents.protocols.ss7.map.api.MAPParameterFactory;
import org.mobicents.protocols.ss7.map.api.primitives.AddressNature;
import org.mobicents.protocols.ss7.map.api.primitives.IMSI;
import org.mobicents.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.mobicents.protocols.ss7.map.api.primitives.NumberingPlan;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.ProvideSubscriberInfoResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMResponse;
import org.mobicents.protocols.ss7.tools.simulator.management.AttackTesterHost;
import org.mobicents.protocols.ss7.tools.simulator.management.Subscriber;
import org.mobicents.protocols.ss7.tools.simulator.management.SubscriberManager;

import java.util.ArrayList;
import java.util.Random;

/**
 * @author Kristoffer Jensen
 */
public class AttackSimulationOrganizer implements Stoppable {
    public static final int TCAP_TIMEOUT = 100000;

    private static Random random;
    private static boolean simpleSimulation;

    private static SimpleAttackGoal simpleAttackGoal;

    private static int numberOfSubscribers;

    private static Subscriber VIP;

    private static long countGenuineProcedures = 0;
    private static long countAttackProcedures = 0;
    private static long countGenuineMessages = 0;
    private static long countAttackMessages = 0;

    private static ISDNAddressString defaultMscAddress;
    private static ISDNAddressString defaultHlrAddress;
    private static ISDNAddressString defaultSmscAddress;
    private static ISDNAddressString defaultVlrAddress;
    private static ISDNAddressString defaultSgsnAddress;
    private static ISDNAddressString defaultMscBAddress;
    private static ISDNAddressString defaultHlrBAddress;
    private static ISDNAddressString defaultSmscBAddress;
    private static ISDNAddressString defaultVlrBAddress;

    private static SubscriberManager subscriberManager;

    private static AttackTesterHost mscAmscB;
    private static AttackTesterHost mscBmscA;

    private static AttackTesterHost mscAhlrA;
    private static AttackTesterHost hlrAmscA;

    private static AttackTesterHost mscAsmscA;
    private static AttackTesterHost smscAmscA;

    private static AttackTesterHost mscAvlrA;
    private static AttackTesterHost vlrAmscA;

    private static AttackTesterHost smscAhlrA;
    private static AttackTesterHost hlrAsmscA;

    private static AttackTesterHost hlrAvlrA;
    private static AttackTesterHost vlrAhlrA;

    private static AttackTesterHost sgsnAhlrA;
    private static AttackTesterHost hlrAsgsnA;

    private static AttackTesterHost gsmscfAhlrA;
    private static AttackTesterHost hlrAgsmscfA;

    private static AttackTesterHost gsmscfAvlrA;
    private static AttackTesterHost vlrAgsmscfA;

    private static AttackTesterHost mscBhlrA;
    private static AttackTesterHost hlrAmscB;

    private static AttackTesterHost mscBsmscA;
    private static AttackTesterHost smscAmscB;

    private static AttackTesterHost mscBvlrA;
    private static AttackTesterHost vlrAmscB;

    private static AttackTesterHost hlrBsmscA;
    private static AttackTesterHost smscAhlrB;

    private static AttackTesterHost hlrBvlrA;
    private static AttackTesterHost vlrAhlrB;

    private static AttackTesterHost vlrBvlrA;
    private static AttackTesterHost vlrAvlrB;

    private static AttackTesterHost smscBsmscA;
    private static AttackTesterHost smscAsmscB;

    private static AttackTesterHost smscBhlrA;
    private static AttackTesterHost hlrAsmscB;

    private static AttackTesterHost vlrBhlrA;
    private static AttackTesterHost hlrAvlrB;

    private static AttackTesterHost attackerBmscA;
    private static AttackTesterHost mscAattackerB;

    private static AttackTesterHost attackerBhlrA;
    private static AttackTesterHost hlrAattackerB;

    private static AttackTesterHost attackerBsmscA;
    private static AttackTesterHost smscAattackerB;

    private static AttackTesterHost attackerBvlrA;
    private static AttackTesterHost vlrAattackerB;

    private AttackTesterHost isupClient;
    private AttackTesterHost isupServer;

    public static final String LOCALHOST = "127.0.0.1";
    public static final String DEFAULT_SMS_MESSAGE  = "SMS Message";

    public static final int HLR_SSN = 6;
    public static final int VLR_SSN = 7;
    public static final int MSC_SSN = 8;
    public static final int SMSC_SSN = MSC_SSN;
    public static final int SGSN_SSN = 149;
    public static final int GSMSCF_SSN = 147;
    public static final int ATTACKER_SSN = 8;

    public static final int MSC_A_OPC = 1;
    public static final int HLR_A_OPC = 2;
    public static final int SMSC_A_OPC = 3;
    public static final int VLR_A_OPC = 4;
    public static final int SGSN_A_OPC = 5;
    public static final int GSMSCF_A_OPC = 6;
    public static final int MSC_B_OPC = 11;
    public static final int HLR_B_OPC = 12;
    public static final int SMSC_B_OPC = 13;
    public static final int VLR_B_OPC = 14;
    public static final int ATTACKER_OPC = 20;

    public static final int MSC_A_SPC = MSC_A_OPC;
    public static final int HLR_A_SPC = HLR_A_OPC;
    public static final int SMSC_A_SPC = SMSC_A_OPC;
    public static final int VLR_A_SPC = VLR_A_OPC;
    public static final int SGSN_A_SPC = SGSN_A_OPC;
    public static final int GSMSCF_A_SPC = GSMSCF_A_OPC;
    public static final int MSC_B_SPC = MSC_B_OPC;
    public static final int HLR_B_SPC = HLR_B_OPC;
    public static final int SMSC_B_SPC = SMSC_B_OPC;
    public static final int VLR_B_SPC = VLR_B_OPC;
    public static final int ATTACKER_SPC = ATTACKER_OPC;

    public static final String OPERATOR_A_GT = "11111111";
    public static final String OPERATOR_B_GT = "22222222";
    public static final String OPERATOR_C_GT = "33333333";

    public static final String MSC_A_MAP_REFERENCE = OPERATOR_A_GT;
    public static final String HLR_A_MAP_REFERENCE = OPERATOR_A_GT;
    public static final String VLR_A_MAP_REFERENCE = OPERATOR_A_GT;
    public static final String MSC_B_MAP_REFERENCE = OPERATOR_B_GT;
    public static final String HLR_B_MAP_REFERENCE = OPERATOR_B_GT;
    public static final String VLR_B_MAP_REFERENCE = OPERATOR_B_GT;
    public static final String ATTACKER_MAP_REFERENCE = OPERATOR_C_GT;

    public static final int LAC_A_1 = 8138;
    public static final int LAC_A_2 = 8161;
    public static final int LAC_A_3 = 8189;
    public static final int LAC_B_1 = 9321;
    public static final int LAC_B_2 = 9343;
    public static final int LAC_B_3 = 9385;
    public static final int LAC_C_1 = 6593;

    public static final int CELLID_A_1 = 12789342;
    public static final int CELLID_A_2 = 94379845;
    public static final int CELLID_A_3 = 84234504;
    public static final int CELLID_B_1 = 74893458;
    public static final int CELLID_B_2 = 23983244;
    public static final int CELLID_B_3 = 32407984;
    public static final int CELLID_C_1 = 23703728;

    public static final int MSC_A_MSC_B_PORT = 8011;
    public static final int MSC_B_MSC_A_PORT = 8012;

    public static final int MSC_A_HLR_A_PORT = 8013;
    public static final int HLR_A_MSC_A_PORT = 8014;

    public static final int MSC_A_SMSC_A_PORT = 8015;
    public static final int SMSC_A_MSC_A_PORT = 8016;

    public static final int MSC_A_VLR_A_PORT = 8017;
    public static final int VLR_A_MSC_A_PORT = 8018;

    public static final int SMSC_A_HLR_A_PORT = 8019;
    public static final int HLR_A_SMSC_A_PORT = 8020;

    public static final int HLR_A_VLR_A_PORT = 8021;
    public static final int VLR_A_HLR_A_PORT = 8022;

    public static final int SGSN_A_HLR_A_PORT = 8023;
    public static final int HLR_A_SGSN_A_PORT = 8024;

    public static final int GSMSCF_A_HLR_A_PORT = 8025;
    public static final int HLR_A_GSMSCF_A_PORT = 8026;

    public static final int GSMSCF_A_VLR_A_PORT = 8027;
    public static final int VLR_A_GSMSCF_A_PORT = 8028;

    public static final int MSC_B_HLR_A_PORT = 8029;
    public static final int HLR_A_MSC_B_PORT = 8030;

    public static final int MSC_B_SMSC_A_PORT = 8031;
    public static final int SMSC_A_MSC_B_PORT = 8032;

    public static final int MSC_B_VLR_A_PORT = 8033;
    public static final int VLR_A_MSC_B_PORT = 8034;

    public static final int HLR_B_SMSC_A_PORT = 8035;
    public static final int SMSC_A_HLR_B_PORT = 8036;

    public static final int HLR_B_VLR_A_PORT = 8037;
    public static final int VLR_A_HLR_B_PORT = 8038;

    public static final int VLR_B_VLR_A_PORT = 8039;
    public static final int VLR_A_VLR_B_PORT = 8040;

    public static final int SMSC_B_SMSC_A_PORT = 8041;
    public static final int SMSC_A_SMSC_B_PORT = 8042;

    public static final int SMSC_B_HLR_A_PORT = 8043;
    public static final int HLR_A_SMSC_B_PORT = 8044;

    public static final int VLR_B_HLR_A_PORT = 8045;
    public static final int HLR_A_VLR_B_PORT = 8046;

    public static final int ATTACKER_MSC_A_PORT = 8047;
    public static final int MSC_A_ATTACK_PORT = 8048;

    public static final int ATTACKER_HLR_A_PORT = 8049;
    public static final int HLR_A_ATTACKER_PORT = 8050;

    public static final int ATTACKER_SMSC_A_PORT = 8051;
    public static final int SMSC_A_ATTACKER_PORT = 8052;

    public static final int ATTACKER_VLR_A_PORT = 8053;
    public static final int VLR_A_ATTACKER_PORT = 8054;

    public AttackSimulationOrganizer(String simulatorHome, boolean simpleSimulation, String simpleAttackGoal, int numberOfSubscribers) {
        random = new Random(System.currentTimeMillis());
        AttackSimulationOrganizer.simpleSimulation = simpleSimulation;
        AttackSimulationOrganizer.numberOfSubscribers = numberOfSubscribers;

        MAPParameterFactory mapParameterFactory = new MAPParameterFactoryImpl();

        AttackSimulationOrganizer.defaultMscAddress = mapParameterFactory.createISDNAddressString(
                AddressNature.international_number,
                NumberingPlan.ISDN,
                AttackSimulationOrganizer.OPERATOR_A_GT);
        AttackSimulationOrganizer.defaultSmscAddress = mapParameterFactory.createISDNAddressString(
                AddressNature.international_number,
                NumberingPlan.ISDN,
                AttackSimulationOrganizer.OPERATOR_A_GT);
        AttackSimulationOrganizer.defaultHlrAddress = mapParameterFactory.createISDNAddressString(
                AddressNature.international_number,
                NumberingPlan.ISDN,
                AttackSimulationOrganizer.OPERATOR_A_GT);
        AttackSimulationOrganizer.defaultVlrAddress = mapParameterFactory.createISDNAddressString(
                AddressNature.international_number,
                NumberingPlan.ISDN,
                AttackSimulationOrganizer.OPERATOR_A_GT);
        AttackSimulationOrganizer.defaultSgsnAddress = mapParameterFactory.createISDNAddressString(
                AddressNature.international_number,
                NumberingPlan.ISDN,
                AttackSimulationOrganizer.OPERATOR_A_GT);

        AttackSimulationOrganizer.defaultMscBAddress = mapParameterFactory.createISDNAddressString(
                AddressNature.international_number,
                NumberingPlan.ISDN,
                AttackSimulationOrganizer.OPERATOR_B_GT);
        AttackSimulationOrganizer.defaultSmscBAddress = mapParameterFactory.createISDNAddressString(
                AddressNature.international_number,
                NumberingPlan.ISDN,
                AttackSimulationOrganizer.OPERATOR_B_GT);
        AttackSimulationOrganizer.defaultHlrBAddress = mapParameterFactory.createISDNAddressString(
                AddressNature.international_number,
                NumberingPlan.ISDN,
                AttackSimulationOrganizer.OPERATOR_B_GT);
        AttackSimulationOrganizer.defaultVlrBAddress = mapParameterFactory.createISDNAddressString(
                AddressNature.international_number,
                NumberingPlan.ISDN,
                AttackSimulationOrganizer.OPERATOR_B_GT);

        AttackSimulationOrganizer.subscriberManager = new SubscriberManager(defaultMscAddress, defaultMscBAddress,
                defaultVlrAddress, defaultVlrBAddress,
                defaultHlrAddress, defaultHlrBAddress);

        AttackSimulationOrganizer.subscriberManager.createRandomSubscribers(numberOfSubscribers,simpleSimulation);

        if (AttackSimulationOrganizer.simpleSimulation) {
            //this.isupClient = new AttackTesterHost("ISUP_CLIENT", simulatorHome, AttackTesterHost.AttackNode.ISUP_CLIENT, this);
            //this.isupServer = new AttackTesterHost("ISUP_SERVER", simulatorHome, AttackTesterHost.AttackNode.ISUP_SERVER, this);

            if(simpleAttackGoal.equals("location:ati")) {
                AttackSimulationOrganizer.simpleAttackGoal = SimpleAttackGoal.LOCATION_ATI;
                AttackSimulationOrganizer.attackerBhlrA = new AttackTesterHost("ATTACKER_B_HLR_A", simulatorHome, AttackTesterHost.AttackNode.ATTACKER_B_HLR_A, this);
                AttackSimulationOrganizer.hlrAattackerB = new AttackTesterHost("HLR_A_ATTACKER_B", simulatorHome, AttackTesterHost.AttackNode.HLR_A_ATTACKER_B, this);
                AttackSimulationOrganizer.hlrAvlrA = new AttackTesterHost("HLR_A_VLR_A", simulatorHome, AttackTesterHost.AttackNode.HLR_A_VLR_A, this);
                AttackSimulationOrganizer.vlrAhlrA = new AttackTesterHost("VLR_A_HLR_A", simulatorHome, AttackTesterHost.AttackNode.VLR_A_HLR_A, this);
            } else if(simpleAttackGoal.equals("location:psi")) {
                AttackSimulationOrganizer.simpleAttackGoal = SimpleAttackGoal.LOCATION_PSI;
                AttackSimulationOrganizer.attackerBhlrA = new AttackTesterHost("ATTACKER_B_HLR_A", simulatorHome, AttackTesterHost.AttackNode.ATTACKER_B_HLR_A, this);
                AttackSimulationOrganizer.hlrAattackerB = new AttackTesterHost("HLR_A_ATTACKER_B", simulatorHome, AttackTesterHost.AttackNode.HLR_A_ATTACKER_B, this);
                AttackSimulationOrganizer.attackerBvlrA = new AttackTesterHost("ATTACKER_B_VLR_A", simulatorHome, AttackTesterHost.AttackNode.ATTACKER_B_VLR_A, this);
                AttackSimulationOrganizer.vlrAattackerB = new AttackTesterHost("VLR_A_ATTACKER_B", simulatorHome, AttackTesterHost.AttackNode.VLR_A_ATTACKER_B, this);
            } else if(simpleAttackGoal.equals("intercept:sms")) {
                AttackSimulationOrganizer.simpleAttackGoal = SimpleAttackGoal.INTERCEPT_SMS;
                AttackSimulationOrganizer.attackerBhlrA = new AttackTesterHost("ATTACKER_B_HLR_A", simulatorHome, AttackTesterHost.AttackNode.ATTACKER_B_HLR_A, this);
                AttackSimulationOrganizer.hlrAattackerB = new AttackTesterHost("HLR_A_ATTACKER_B", simulatorHome, AttackTesterHost.AttackNode.HLR_A_ATTACKER_B, this);
                AttackSimulationOrganizer.smscAhlrA = new AttackTesterHost("SMSC_A_HLR_A", simulatorHome, AttackTesterHost.AttackNode.SMSC_A_HLR_A, this);
                AttackSimulationOrganizer.hlrAsmscA = new AttackTesterHost("HLR_A_SMSC_A", simulatorHome, AttackTesterHost.AttackNode.HLR_A_SMSC_A, this);
                AttackSimulationOrganizer.mscAsmscA = new AttackTesterHost("MSC_A_SMSC_A", simulatorHome, AttackTesterHost.AttackNode.MSC_A_SMSC_A, this);
                AttackSimulationOrganizer.smscAmscA = new AttackTesterHost("SMSC_A_MSC_A", simulatorHome, AttackTesterHost.AttackNode.SMSC_A_MSC_A, this);
                AttackSimulationOrganizer.hlrAvlrA = new AttackTesterHost("HLR_A_VLR_A", simulatorHome, AttackTesterHost.AttackNode.HLR_A_VLR_A, this);
                AttackSimulationOrganizer.vlrAhlrA = new AttackTesterHost("VLR_A_HLR_A", simulatorHome, AttackTesterHost.AttackNode.VLR_A_HLR_A, this);
                AttackSimulationOrganizer.attackerBsmscA = new AttackTesterHost("ATTACKER_B_SMSC_A", simulatorHome, AttackTesterHost.AttackNode.ATTACKER_B_SMSC_A, this);
                AttackSimulationOrganizer.smscAattackerB = new AttackTesterHost("SMSC_A_ATTACKER_B", simulatorHome, AttackTesterHost.AttackNode.SMSC_A_ATTACKER_B, this);
            } else if(simpleAttackGoal.equals("test:ports")) {
                AttackSimulationOrganizer.simpleAttackGoal = SimpleAttackGoal.TEST_PORTS;
                AttackSimulationOrganizer.mscAhlrA = new AttackTesterHost("MSC_A_HLR_A", simulatorHome, AttackTesterHost.AttackNode.MSC_A_HLR_A, this);
                AttackSimulationOrganizer.hlrAmscA = new AttackTesterHost("HLR_A_MSC_A", simulatorHome, AttackTesterHost.AttackNode.HLR_A_MSC_A, this);
                AttackSimulationOrganizer.smscAhlrA = new AttackTesterHost("SMSC_A_HLR_A", simulatorHome, AttackTesterHost.AttackNode.SMSC_A_HLR_A, this);
                AttackSimulationOrganizer.hlrAsmscA = new AttackTesterHost("HLR_A_SMSC_A", simulatorHome, AttackTesterHost.AttackNode.HLR_A_SMSC_A, this);
            } else {
                System.out.println("ERROR: Unknown simple attack goal: " + simpleAttackGoal);
                System.exit(-1);
            }
        } else {
            initateAllNodes(simulatorHome);
        }
    }

    public AttackTesterHost getMscAmscB() {
        return mscAmscB;
    }

    public AttackTesterHost getMscBmscA() {
        return mscBmscA;
    }

    public AttackTesterHost getMscAhlrA() {
        return mscAhlrA;
    }

    public AttackTesterHost getHlrAmscA() {
        return hlrAmscA;
    }

    public AttackTesterHost getMscAsmscA() {
        return mscAsmscA;
    }

    public AttackTesterHost getSmscAmscA() {
        return smscAmscA;
    }

    public AttackTesterHost getMscAvlrA() {
        return mscAvlrA;
    }

    public AttackTesterHost getVlrAmscA() {
        return vlrAmscA;
    }

    public AttackTesterHost getSmscAhlrA() {
        return smscAhlrA;
    }

    public AttackTesterHost getHlrAsmscA() {
        return hlrAsmscA;
    }

    public AttackTesterHost getHlrAvlrA() {
        return hlrAvlrA;
    }

    public AttackTesterHost getVlrAhlrA() {
        return vlrAhlrA;
    }

    public AttackTesterHost getSgsnAhlrA() {
        return sgsnAhlrA;
    }

    public AttackTesterHost getHlrAsgsnA() {
        return hlrAsgsnA;
    }

    public AttackTesterHost getGsmscfAhlrA() {
        return gsmscfAhlrA;
    }

    public AttackTesterHost getHlrAgsmscfA() {
        return hlrAgsmscfA;
    }

    public AttackTesterHost getGsmscfAvlrA() {
        return gsmscfAvlrA;
    }

    public AttackTesterHost getVlrAgsmscfA() {
        return vlrAgsmscfA;
    }

    public AttackTesterHost getMscBhlrA() {
        return mscBhlrA;
    }

    public AttackTesterHost getHlrAmscB() {
        return hlrAmscB;
    }

    public AttackTesterHost getMscBsmscA() {
        return mscBsmscA;
    }

    public AttackTesterHost getSmscAmscB() {
        return smscAmscB;
    }

    public AttackTesterHost getMscBvlrA() {
        return mscBvlrA;
    }

    public AttackTesterHost getVlrAmscB() {
        return vlrAmscB;
    }

    public AttackTesterHost getHlrBsmscA() {
        return hlrBsmscA;
    }

    public AttackTesterHost getSmscAhlrB() {
        return smscAhlrB;
    }

    public AttackTesterHost getHlrBvlrA() {
        return hlrBvlrA;
    }

    public AttackTesterHost getVlrAhlrB() {
        return vlrAhlrB;
    }

    public AttackTesterHost getVlrBvlrA() {
        return vlrBvlrA;
    }

    public AttackTesterHost getVlrAvlrB() {
        return vlrAvlrB;
    }

    public AttackTesterHost getSmscBsmscA() {
        return smscBsmscA;
    }

    public AttackTesterHost getSmscAsmscB() {
        return smscAsmscB;
    }

    public AttackTesterHost getSmscBhlrA() {
        return smscBhlrA;
    }

    public AttackTesterHost getHlrAsmscB() {
        return hlrAsmscB;
    }

    public AttackTesterHost getVlrBhlrA() {
        return vlrBhlrA;
    }

    public AttackTesterHost getHlrAvlrB() {
        return hlrAvlrB;
    }

    public AttackTesterHost getAttackerBmscA() {
        return attackerBmscA;
    }

    public AttackTesterHost getMscAattackerB() {
        return mscAattackerB;
    }

    public AttackTesterHost getAttackerBhlrA() {
        return attackerBhlrA;
    }

    public AttackTesterHost getHlrAattackerB() {
        return hlrAattackerB;
    }

    public AttackTesterHost getAttackerBsmscA() {
        return attackerBsmscA;
    }

    public AttackTesterHost getSmscAattackerB() {
        return smscAattackerB;
    }

    public AttackTesterHost getAttackerBvlrA() {
        return attackerBvlrA;
    }

    public AttackTesterHost getVlrAattackerB() {
        return vlrAattackerB;
    }

    private void initateAllNodes(String simulatorHome) {
        AttackSimulationOrganizer.mscAmscB = new AttackTesterHost("MSC_A_MSC_B", simulatorHome, AttackTesterHost.AttackNode.MSC_A_MSC_B, this);
        AttackSimulationOrganizer.mscBmscA = new AttackTesterHost("MSC_B_MSC_A", simulatorHome, AttackTesterHost.AttackNode.MSC_B_MSC_A, this);

        AttackSimulationOrganizer.mscAhlrA = new AttackTesterHost("MSC_A_HLR_A", simulatorHome, AttackTesterHost.AttackNode.MSC_A_HLR_A, this);
        AttackSimulationOrganizer.hlrAmscA = new AttackTesterHost("HLR_A_MSC_A", simulatorHome, AttackTesterHost.AttackNode.HLR_A_MSC_A, this);

        AttackSimulationOrganizer.mscAsmscA = new AttackTesterHost("MSC_A_SMSC_A", simulatorHome, AttackTesterHost.AttackNode.MSC_A_SMSC_A, this);
        AttackSimulationOrganizer.smscAmscA = new AttackTesterHost("SMSC_A_MSC_A", simulatorHome, AttackTesterHost.AttackNode.SMSC_A_MSC_A, this);

        AttackSimulationOrganizer.mscAvlrA = new AttackTesterHost("MSC_A_VLR_A", simulatorHome, AttackTesterHost.AttackNode.MSC_A_VLR_A, this);
        AttackSimulationOrganizer.vlrAmscA = new AttackTesterHost("VLR_A_MSC_A", simulatorHome, AttackTesterHost.AttackNode.VLR_A_MSC_A, this);

        AttackSimulationOrganizer.smscAhlrA = new AttackTesterHost("SMSC_A_HLR_A", simulatorHome, AttackTesterHost.AttackNode.SMSC_A_HLR_A, this);
        AttackSimulationOrganizer.hlrAsmscA = new AttackTesterHost("HLR_A_SMSC_A", simulatorHome, AttackTesterHost.AttackNode.HLR_A_SMSC_A, this);

        AttackSimulationOrganizer.hlrAvlrA = new AttackTesterHost("HLR_A_VLR_A", simulatorHome, AttackTesterHost.AttackNode.HLR_A_VLR_A, this);
        AttackSimulationOrganizer.vlrAhlrA = new AttackTesterHost("VLR_A_HLR_A", simulatorHome, AttackTesterHost.AttackNode.VLR_A_HLR_A, this);

        AttackSimulationOrganizer.sgsnAhlrA = new AttackTesterHost("SGSN_A_HLR_A", simulatorHome, AttackTesterHost.AttackNode.SGSN_A_HLR_A, this);
        AttackSimulationOrganizer.hlrAsgsnA = new AttackTesterHost("HLR_A_SGSN_A", simulatorHome, AttackTesterHost.AttackNode.HLR_A_SGSN_A, this);

        AttackSimulationOrganizer.gsmscfAhlrA = new AttackTesterHost("GSMSCF_A_HLR_A", simulatorHome, AttackTesterHost.AttackNode.GSMSCF_A_HLR_A, this);
        AttackSimulationOrganizer.hlrAgsmscfA = new AttackTesterHost("HLR_A_GSMSCF_A", simulatorHome, AttackTesterHost.AttackNode.HLR_A_GSMSCF_A, this);

        AttackSimulationOrganizer.gsmscfAvlrA = new AttackTesterHost("GSMSCF_A_VLR_A", simulatorHome, AttackTesterHost.AttackNode.GSMSCF_A_VLR_A, this);
        AttackSimulationOrganizer.vlrAgsmscfA = new AttackTesterHost("VLR_A_GSMSCF_A", simulatorHome, AttackTesterHost.AttackNode.VLR_A_GSMSCF_A, this);

        AttackSimulationOrganizer.attackerBmscA = new AttackTesterHost("ATTACKER_B_MSC_A", simulatorHome, AttackTesterHost.AttackNode.ATTACKER_B_MSC_A, this);
        AttackSimulationOrganizer.mscAattackerB = new AttackTesterHost("MSC_A_ATTACKER_B", simulatorHome, AttackTesterHost.AttackNode.MSC_A_ATTACKER_B, this);

        AttackSimulationOrganizer.attackerBhlrA = new AttackTesterHost("ATTACKER_B_HLR_A", simulatorHome, AttackTesterHost.AttackNode.ATTACKER_B_HLR_A, this);
        AttackSimulationOrganizer.hlrAattackerB = new AttackTesterHost("HLR_A_ATTACKER_B", simulatorHome, AttackTesterHost.AttackNode.HLR_A_ATTACKER_B, this);

        AttackSimulationOrganizer.attackerBsmscA = new AttackTesterHost("ATTACKER_B_SMSC_A", simulatorHome, AttackTesterHost.AttackNode.ATTACKER_B_SMSC_A, this);
        AttackSimulationOrganizer.smscAattackerB = new AttackTesterHost("SMSC_A_ATTACKER_B", simulatorHome, AttackTesterHost.AttackNode.SMSC_A_ATTACKER_B, this);

        AttackSimulationOrganizer.attackerBvlrA = new AttackTesterHost("ATTACKER_B_VLR_A", simulatorHome, AttackTesterHost.AttackNode.ATTACKER_B_VLR_A, this);
        AttackSimulationOrganizer.vlrAattackerB = new AttackTesterHost("VLR_A_ATTACKER_B", simulatorHome, AttackTesterHost.AttackNode.VLR_A_ATTACKER_B, this);

        AttackSimulationOrganizer.smscAsmscB = new AttackTesterHost("SMSC_A_SMSC_B", simulatorHome, AttackTesterHost.AttackNode.SMSC_A_SMSC_B, this);
        AttackSimulationOrganizer.smscBsmscA = new AttackTesterHost("SMSC_B_SMSC_A", simulatorHome, AttackTesterHost.AttackNode.SMSC_B_SMSC_A, this);

        AttackSimulationOrganizer.smscAhlrB = new AttackTesterHost("SMSC_A_HLR_B", simulatorHome, AttackTesterHost.AttackNode.SMSC_A_HLR_B, this);
        AttackSimulationOrganizer.hlrBsmscA = new AttackTesterHost("HLR_B_SMSC_A", simulatorHome, AttackTesterHost.AttackNode.HLR_B_SMSC_A, this);

        AttackSimulationOrganizer.smscBhlrA = new AttackTesterHost("SMSC_B_HLR_A", simulatorHome, AttackTesterHost.AttackNode.SMSC_B_HLR_A, this);
        AttackSimulationOrganizer.hlrAsmscB = new AttackTesterHost("HLR_A_SMSC_B", simulatorHome, AttackTesterHost.AttackNode.HLR_A_SMSC_B, this);

        AttackSimulationOrganizer.mscBhlrA = new AttackTesterHost("MSC_B_HLR_A", simulatorHome, AttackTesterHost.AttackNode.MSC_B_HLR_A, this);
        AttackSimulationOrganizer.hlrAmscB = new AttackTesterHost("HLR_A_MSC_B", simulatorHome, AttackTesterHost.AttackNode.HLR_A_MSC_B, this);

        AttackSimulationOrganizer.mscBsmscA = new AttackTesterHost("MSC_B_SMSC_A", simulatorHome, AttackTesterHost.AttackNode.MSC_B_SMSC_A, this);
        AttackSimulationOrganizer.smscAmscB = new AttackTesterHost("SMSC_A_MSC_B", simulatorHome, AttackTesterHost.AttackNode.SMSC_A_MSC_B, this);

        AttackSimulationOrganizer.mscBvlrA = new AttackTesterHost("MSC_B_VLR_A", simulatorHome, AttackTesterHost.AttackNode.MSC_B_VLR_A, this);
        AttackSimulationOrganizer.vlrAmscB = new AttackTesterHost("VLR_A_MSC_B", simulatorHome, AttackTesterHost.AttackNode.VLR_A_MSC_B, this);

        AttackSimulationOrganizer.hlrBvlrA = new AttackTesterHost("HLR_B_VLR_A", simulatorHome, AttackTesterHost.AttackNode.HLR_B_VLR_A, this);
        AttackSimulationOrganizer.vlrAhlrB = new AttackTesterHost("VLR_A_HLR_B", simulatorHome, AttackTesterHost.AttackNode.VLR_A_HLR_B, this);

        AttackSimulationOrganizer.vlrBvlrA = new AttackTesterHost("VLR_B_VLR_A", simulatorHome, AttackTesterHost.AttackNode.VLR_B_VLR_A, this);
        AttackSimulationOrganizer.vlrAvlrB = new AttackTesterHost("VLR_A_VLR_B", simulatorHome, AttackTesterHost.AttackNode.VLR_A_VLR_B, this);

        AttackSimulationOrganizer.vlrBhlrA = new AttackTesterHost("VLR_B_HLR_A", simulatorHome, AttackTesterHost.AttackNode.VLR_B_HLR_A, this);
        AttackSimulationOrganizer.hlrAvlrB = new AttackTesterHost("HLR_A_VLR_B", simulatorHome, AttackTesterHost.AttackNode.HLR_A_VLR_B, this);
    }

    public ISDNAddressString getDefaultMscAddress() {
        return defaultMscAddress;
    }

    public ISDNAddressString getDefaultSmscAddress() {
        return defaultSmscAddress;
    }

    public ISDNAddressString getDefaultHlrAddress() {
        return defaultHlrAddress;
    }

    public ISDNAddressString getDefaultVlrAddress() {
        return defaultVlrAddress;
    }

    public ISDNAddressString getDefaultMscBAddress() {
        return defaultMscBAddress;
    }

    public ISDNAddressString getDefaultHlrBAddress() {
        return defaultHlrBAddress;
    }

    public ISDNAddressString getDefaultSmscBAddress() {
        return defaultSmscBAddress;
    }

    public ISDNAddressString getDefaultVlrBAddress() {
        return defaultVlrBAddress;
    }

    public SubscriberManager getSubscriberManager() {
        return subscriberManager;
    }

    private void startAttackSimulationHosts() {
        if (AttackSimulationOrganizer.simpleSimulation) {
            switch(simpleAttackGoal) {
                case LOCATION_ATI:
                    AttackSimulationOrganizer.attackerBhlrA.start();
                    AttackSimulationOrganizer.hlrAattackerB.start();
                    AttackSimulationOrganizer.hlrAvlrA.start();
                    AttackSimulationOrganizer.vlrAhlrA.start();
                    break;
                case LOCATION_PSI:
                    AttackSimulationOrganizer.attackerBhlrA.start();
                    AttackSimulationOrganizer.hlrAattackerB.start();
                    AttackSimulationOrganizer.attackerBvlrA.start();
                    AttackSimulationOrganizer.vlrAattackerB.start();
                    break;
                case INTERCEPT_SMS:
                    AttackSimulationOrganizer.attackerBhlrA.start();
                    AttackSimulationOrganizer.hlrAattackerB.start();
                    AttackSimulationOrganizer.smscAhlrA.start();
                    AttackSimulationOrganizer.hlrAsmscA.start();
                    AttackSimulationOrganizer.mscAsmscA.start();
                    AttackSimulationOrganizer.smscAmscA.start();
                    AttackSimulationOrganizer.hlrAvlrA.start();
                    AttackSimulationOrganizer.vlrAhlrA.start();
                    AttackSimulationOrganizer.attackerBsmscA.start();
                    AttackSimulationOrganizer.smscAattackerB.start();
                    break;
                case TEST_PORTS:
                    AttackSimulationOrganizer.mscAhlrA.start();
                    AttackSimulationOrganizer.hlrAmscA.start();
                    AttackSimulationOrganizer.smscAhlrA.start();
                    AttackSimulationOrganizer.hlrAsmscA.start();
                    break;
            }
        } else {
            startAllAttackSimulationHosts();
        }
    }

    private void startAllAttackSimulationHosts() {
        AttackSimulationOrganizer.mscAmscB.start();
        AttackSimulationOrganizer.mscBmscA.start();

        AttackSimulationOrganizer.mscAhlrA.start();
        AttackSimulationOrganizer.hlrAmscA.start();

        AttackSimulationOrganizer.mscAsmscA.start();
        AttackSimulationOrganizer.smscAmscA.start();

        AttackSimulationOrganizer.mscAvlrA.start();
        AttackSimulationOrganizer.vlrAmscA.start();

        AttackSimulationOrganizer.smscAhlrA.start();
        AttackSimulationOrganizer.hlrAsmscA.start();

        AttackSimulationOrganizer.hlrAvlrA.start();
        AttackSimulationOrganizer.vlrAhlrA.start();

        AttackSimulationOrganizer.sgsnAhlrA.start();
        AttackSimulationOrganizer.hlrAsgsnA.start();

        AttackSimulationOrganizer.gsmscfAhlrA.start();
        AttackSimulationOrganizer.hlrAgsmscfA.start();

        AttackSimulationOrganizer.gsmscfAvlrA.start();
        AttackSimulationOrganizer.vlrAgsmscfA.start();

        AttackSimulationOrganizer.attackerBmscA.start();
        AttackSimulationOrganizer.mscAattackerB.start();

        AttackSimulationOrganizer.attackerBhlrA.start();
        AttackSimulationOrganizer.hlrAattackerB.start();

        AttackSimulationOrganizer.attackerBsmscA.start();
        AttackSimulationOrganizer.smscAattackerB.start();

        AttackSimulationOrganizer.attackerBvlrA.start();
        AttackSimulationOrganizer.vlrAattackerB.start();

        AttackSimulationOrganizer.smscAsmscB.start();
        AttackSimulationOrganizer.smscBsmscA.start();

        AttackSimulationOrganizer.smscAhlrB.start();
        AttackSimulationOrganizer.hlrBsmscA.start();

        AttackSimulationOrganizer.smscBhlrA.start();
        AttackSimulationOrganizer.hlrAsmscB.start();

        AttackSimulationOrganizer.mscBhlrA.start();
        AttackSimulationOrganizer.hlrAmscB.start();

        AttackSimulationOrganizer.mscBsmscA.start();
        AttackSimulationOrganizer.smscAmscB.start();

        AttackSimulationOrganizer.mscBvlrA.start();
        AttackSimulationOrganizer.vlrAmscB.start();

        AttackSimulationOrganizer.hlrBvlrA.start();
        AttackSimulationOrganizer.vlrAhlrB.start();

        AttackSimulationOrganizer.vlrBvlrA.start();
        AttackSimulationOrganizer.vlrAvlrB.start();

        AttackSimulationOrganizer.vlrBhlrA.start();
        AttackSimulationOrganizer.hlrAvlrB.start();
    }

    private boolean waitForM3UALinks() {
        while (true) {
            try {
                Thread.sleep(50);
                if(!AttackSimulationOrganizer.simpleSimulation) {
                    if (mscAmscB.getM3uaMan().getState().contains("ACTIVE") &&
                            mscAhlrA.getM3uaMan().getState().contains("ACTIVE") &&
                            mscAsmscA.getM3uaMan().getState().contains("ACTIVE") &&
                            mscAvlrA.getM3uaMan().getState().contains("ACTIVE") &&
                            smscAhlrA.getM3uaMan().getState().contains("ACTIVE") &&
                            hlrAvlrA.getM3uaMan().getState().contains("ACTIVE") &&
                            sgsnAhlrA.getM3uaMan().getState().contains("ACTIVE") &&
                            gsmscfAhlrA.getM3uaMan().getState().contains("ACTIVE") &&
                            gsmscfAvlrA.getM3uaMan().getState().contains("ACTIVE") &&
                            attackerBmscA.getM3uaMan().getState().contains("ACTIVE") &&
                            attackerBhlrA.getM3uaMan().getState().contains("ACTIVE") &&
                            attackerBsmscA.getM3uaMan().getState().contains("ACTIVE") &&
                            attackerBvlrA.getM3uaMan().getState().contains("ACTIVE") &&
                            smscAsmscB.getM3uaMan().getState().contains("ACTIVE") &&
                            smscAhlrB.getM3uaMan().getState().contains("ACTIVE") &&
                            smscBhlrA.getM3uaMan().getState().contains("ACTIVE") &&
                            mscBhlrA.getM3uaMan().getState().contains("ACTIVE") &&
                            mscBsmscA.getM3uaMan().getState().contains("ACTIVE") &&
                            mscBvlrA.getM3uaMan().getState().contains("ACTIVE") &&
                            hlrBvlrA.getM3uaMan().getState().contains("ACTIVE") &&
                            vlrBvlrA.getM3uaMan().getState().contains("ACTIVE") &&
                            vlrBhlrA.getM3uaMan().getState().contains("ACTIVE"))
                        return true;
                } else {
                    switch(AttackSimulationOrganizer.simpleAttackGoal) {
                        case LOCATION_ATI:
                            if(AttackSimulationOrganizer.attackerBhlrA.getM3uaMan().getState().contains("ACTIVE") &&
                                    AttackSimulationOrganizer.hlrAvlrA.getM3uaMan().getState().contains("ACTIVE"))
                                return true;
                            break;
                        case LOCATION_PSI:
                            if(AttackSimulationOrganizer.attackerBhlrA.getM3uaMan().getState().contains("ACTIVE") &&
                                    AttackSimulationOrganizer.attackerBvlrA.getM3uaMan().getState().contains("ACTIVE"))
                                return true;
                            break;
                        case INTERCEPT_SMS:
                            if(AttackSimulationOrganizer.attackerBhlrA.getM3uaMan().getState().contains("ACTIVE") &&
                                    AttackSimulationOrganizer.smscAhlrA.getM3uaMan().getState().contains("ACTIVE") &&
                                    AttackSimulationOrganizer.mscAsmscA.getM3uaMan().getState().contains("ACTIVE") &&
                                    AttackSimulationOrganizer.attackerBsmscA.getM3uaMan().getState().contains("ACTIVE") &&
                                    AttackSimulationOrganizer.hlrAvlrA.getM3uaMan().getState().contains("ACTIVE"))
                                return true;
                            break;
                        case TEST_PORTS:
                            if (mscAhlrA.getM3uaMan().getState().contains("ACTIVE") &&
                                    smscAhlrA.getM3uaMan().getState().contains("ACTIVE"))
                                return true;
                            break;
                    }
                    //if (this.isupClient.getM3uaMan().getState().contains("ACTIVE") &&
                    //        this.isupServer.getM3uaMan().getState().contains("ACTIVE"))
                    //    return true;
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
                return false;
            }
        }
    }

    private boolean testerHostsNeedQuit() {
        if(simpleSimulation) {
            switch(AttackSimulationOrganizer.simpleAttackGoal) {
                case LOCATION_ATI:
                    return AttackSimulationOrganizer.attackerBhlrA.isNeedQuit() || AttackSimulationOrganizer.hlrAattackerB.isNeedQuit() ||
                            AttackSimulationOrganizer.hlrAvlrA.isNeedQuit() || AttackSimulationOrganizer.vlrAhlrA.isNeedQuit();
                case LOCATION_PSI:
                    return AttackSimulationOrganizer.attackerBhlrA.isNeedQuit() || AttackSimulationOrganizer.hlrAattackerB.isNeedQuit() ||
                            AttackSimulationOrganizer.attackerBvlrA.isNeedQuit() || AttackSimulationOrganizer.vlrAattackerB.isNeedQuit();
                case INTERCEPT_SMS:
                    return AttackSimulationOrganizer.attackerBhlrA.isNeedQuit() || AttackSimulationOrganizer.hlrAattackerB.isNeedQuit() ||
                            AttackSimulationOrganizer.smscAhlrA.isNeedQuit() || AttackSimulationOrganizer.hlrAsmscA.isNeedQuit() ||
                            AttackSimulationOrganizer.mscAsmscA.isNeedQuit() || AttackSimulationOrganizer.smscAmscA.isNeedQuit() ||
                            AttackSimulationOrganizer.attackerBsmscA.isNeedQuit() || AttackSimulationOrganizer.smscAattackerB.isNeedQuit() ||
                            AttackSimulationOrganizer.hlrAvlrA.isNeedQuit() || AttackSimulationOrganizer.vlrAhlrA.isNeedQuit();
                case TEST_PORTS:
                    return AttackSimulationOrganizer.mscAhlrA.isNeedQuit() || AttackSimulationOrganizer.hlrAmscA.isNeedQuit() ||
                            AttackSimulationOrganizer.smscAhlrA.isNeedQuit() || AttackSimulationOrganizer.hlrAsmscA.isNeedQuit();
            }
            return false;
            //return this.isupClient.isNeedQuit() || this.isupServer.isNeedQuit();
        } else {
            return AttackSimulationOrganizer.mscAmscB.isNeedQuit() || AttackSimulationOrganizer.mscBmscA.isNeedQuit() ||
                    AttackSimulationOrganizer.mscAhlrA.isNeedQuit() || AttackSimulationOrganizer.hlrAmscA.isNeedQuit() ||
                    AttackSimulationOrganizer.mscAsmscA.isNeedQuit() || AttackSimulationOrganizer.smscAmscA.isNeedQuit() ||
                    AttackSimulationOrganizer.mscAvlrA.isNeedQuit() || AttackSimulationOrganizer.vlrAmscA.isNeedQuit() ||
                    AttackSimulationOrganizer.smscAhlrA.isNeedQuit() || AttackSimulationOrganizer.hlrAsmscA.isNeedQuit() ||
                    AttackSimulationOrganizer.hlrAvlrA.isNeedQuit() || AttackSimulationOrganizer.vlrAhlrA.isNeedQuit() ||
                    AttackSimulationOrganizer.sgsnAhlrA.isNeedQuit() || AttackSimulationOrganizer.hlrAsgsnA.isNeedQuit() ||
                    AttackSimulationOrganizer.gsmscfAhlrA.isNeedQuit() || AttackSimulationOrganizer.hlrAgsmscfA.isNeedQuit() ||
                    AttackSimulationOrganizer.gsmscfAvlrA.isNeedQuit() || AttackSimulationOrganizer.vlrAgsmscfA.isNeedQuit() ||
                    AttackSimulationOrganizer.attackerBmscA.isNeedQuit() || AttackSimulationOrganizer.mscAattackerB.isNeedQuit() ||
                    AttackSimulationOrganizer.attackerBhlrA.isNeedQuit() || AttackSimulationOrganizer.hlrAattackerB.isNeedQuit() ||
                    AttackSimulationOrganizer.attackerBsmscA.isNeedQuit() || AttackSimulationOrganizer.smscAattackerB.isNeedQuit() ||
                    AttackSimulationOrganizer.attackerBvlrA.isNeedQuit() || AttackSimulationOrganizer.vlrAattackerB.isNeedQuit() ||
                    AttackSimulationOrganizer.smscAsmscB.isNeedQuit() || AttackSimulationOrganizer.smscBsmscA.isNeedQuit() ||
                    AttackSimulationOrganizer.smscAhlrB.isNeedQuit() || AttackSimulationOrganizer.hlrBsmscA.isNeedQuit() ||
                    AttackSimulationOrganizer.smscBhlrA.isNeedQuit() || AttackSimulationOrganizer.hlrAsmscB.isNeedQuit() ||
                    AttackSimulationOrganizer.mscBhlrA.isNeedQuit() || AttackSimulationOrganizer.hlrAmscB.isNeedQuit() ||
                    AttackSimulationOrganizer.mscBsmscA.isNeedQuit() || AttackSimulationOrganizer.smscAmscB.isNeedQuit() ||
                    AttackSimulationOrganizer.mscBvlrA.isNeedQuit() || AttackSimulationOrganizer.vlrAmscB.isNeedQuit() ||
                    AttackSimulationOrganizer.hlrBvlrA.isNeedQuit() || AttackSimulationOrganizer.vlrAhlrB.isNeedQuit() ||
                    AttackSimulationOrganizer.vlrBvlrA.isNeedQuit() || AttackSimulationOrganizer.vlrAvlrB.isNeedQuit() ||
                    AttackSimulationOrganizer.vlrBhlrA.isNeedQuit() || AttackSimulationOrganizer.hlrAvlrB.isNeedQuit();
        }
    }

    private void testerHostsExecuteCheckStore() {
        if (simpleSimulation) {
            switch(AttackSimulationOrganizer.simpleAttackGoal) {
                case LOCATION_ATI:
                    AttackSimulationOrganizer.attackerBhlrA.execute();
                    AttackSimulationOrganizer.hlrAattackerB.execute();
                    AttackSimulationOrganizer.hlrAvlrA.execute();
                    AttackSimulationOrganizer.vlrAhlrA.execute();
                    break;
                case LOCATION_PSI:
                    AttackSimulationOrganizer.attackerBhlrA.execute();
                    AttackSimulationOrganizer.hlrAattackerB.execute();
                    AttackSimulationOrganizer.attackerBvlrA.execute();
                    AttackSimulationOrganizer.vlrAattackerB.execute();
                    break;
                case INTERCEPT_SMS:
                    AttackSimulationOrganizer.attackerBhlrA.execute();
                    AttackSimulationOrganizer.hlrAattackerB.execute();
                    AttackSimulationOrganizer.smscAhlrA.execute();
                    AttackSimulationOrganizer.hlrAsmscA.execute();
                    AttackSimulationOrganizer.mscAsmscA.execute();
                    AttackSimulationOrganizer.smscAmscA.execute();
                    AttackSimulationOrganizer.hlrAvlrA.execute();
                    AttackSimulationOrganizer.vlrAhlrA.execute();
                    AttackSimulationOrganizer.attackerBsmscA.execute();
                    AttackSimulationOrganizer.smscAattackerB.execute();
                    break;
                case TEST_PORTS:
                    AttackSimulationOrganizer.mscAhlrA.execute();
                    AttackSimulationOrganizer.hlrAmscA.execute();
                    AttackSimulationOrganizer.smscAhlrA.execute();
                    AttackSimulationOrganizer.hlrAsmscA.execute();
                    break;
            }
            //this.isupClient.execute();
            //this.isupServer.execute();

            //this.isupClient.checkStore();
            //this.isupServer.checkStore();
        } else {
            AttackSimulationOrganizer.mscAmscB.execute();
            AttackSimulationOrganizer.mscBmscA.execute();
            AttackSimulationOrganizer.mscAhlrA.execute();
            AttackSimulationOrganizer.hlrAmscA.execute();
            AttackSimulationOrganizer.mscAsmscA.execute();
            AttackSimulationOrganizer.smscAmscA.execute();
            AttackSimulationOrganizer.mscAvlrA.execute();
            AttackSimulationOrganizer.vlrAmscA.execute();
            AttackSimulationOrganizer.smscAhlrA.execute();
            AttackSimulationOrganizer.hlrAsmscA.execute();
            AttackSimulationOrganizer.hlrAvlrA.execute();
            AttackSimulationOrganizer.vlrAhlrA.execute();
            AttackSimulationOrganizer.sgsnAhlrA.execute();
            AttackSimulationOrganizer.hlrAsgsnA.execute();
            AttackSimulationOrganizer.gsmscfAhlrA.execute();
            AttackSimulationOrganizer.hlrAgsmscfA.execute();
            AttackSimulationOrganizer.gsmscfAvlrA.execute();
            AttackSimulationOrganizer.vlrAgsmscfA.execute();
            AttackSimulationOrganizer.attackerBmscA.execute();
            AttackSimulationOrganizer.mscAattackerB.execute();
            AttackSimulationOrganizer.attackerBhlrA.execute();
            AttackSimulationOrganizer.hlrAattackerB.execute();
            AttackSimulationOrganizer.attackerBsmscA.execute();
            AttackSimulationOrganizer.smscAattackerB.execute();
            AttackSimulationOrganizer.attackerBvlrA.execute();
            AttackSimulationOrganizer.vlrAattackerB.execute();
            AttackSimulationOrganizer.smscAsmscB.execute();
            AttackSimulationOrganizer.smscBsmscA.execute();
            AttackSimulationOrganizer.smscAhlrB.execute();
            AttackSimulationOrganizer.hlrBsmscA.execute();
            AttackSimulationOrganizer.smscBhlrA.execute();
            AttackSimulationOrganizer.hlrAsmscB.execute();
            AttackSimulationOrganizer.mscBhlrA.execute();
            AttackSimulationOrganizer.hlrAmscB.execute();
            AttackSimulationOrganizer.mscBsmscA.execute();
            AttackSimulationOrganizer.smscAmscB.execute();
            AttackSimulationOrganizer.mscBvlrA.execute();
            AttackSimulationOrganizer.vlrAmscB.execute();
            AttackSimulationOrganizer.hlrBvlrA.execute();
            AttackSimulationOrganizer.vlrAhlrB.execute();
            AttackSimulationOrganizer.vlrBvlrA.execute();
            AttackSimulationOrganizer.vlrAvlrB.execute();
            AttackSimulationOrganizer.vlrBhlrA.execute();
            AttackSimulationOrganizer.hlrAvlrB.execute();
        }
    }

    private void configureShutDownHook() {
        Runtime.getRuntime().addShutdownHook(new Thread() {
            public void run() {
                System.out.println();
                System.out.println("Exiting..");
                System.out.println("Number of genuine procedures generated: " + AttackSimulationOrganizer.countGenuineProcedures);
                System.out.println("Number of attack procedures generated: " + AttackSimulationOrganizer.countAttackProcedures);

                //Sleep for some seconds, so nodes can shutdown.
                try{
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });
    }

    private void printAttackSimulationStart() {
        System.out.println("-----------------------------------------------");
        System.out.println("-----------Attack Simulation Started-----------");
        System.out.println("-----------------------------------------------");
        System.out.println("Simulation Type: " + (AttackSimulationOrganizer.simpleSimulation ? "Simple" : "Complex"));
        System.out.println("Parameters:");
        if(AttackSimulationOrganizer.simpleSimulation) {
            System.out.println("    -m: " + AttackSimulationOrganizer.simpleAttackGoal.name());
        } else {
            System.out.println("    -s: " + AttackSimulationOrganizer.numberOfSubscribers);
        }
        System.out.println("-----------------------------------------------");
        System.out.println("-----------------------------------------------");
    }

    private void printSentMessage(String messageSent, boolean genuineMessage) {
        //if(genuineMessage)
        //    System.out.print("Generating noise: ");
        //else
        //    System.out.print("Generating attack: ");

        //System.out.println(messageSent);
    }

    private enum VipAction{
        NONE,
        TRACK,
        INTERCEPT
    }

    private enum VipNextAction {
        FIRST_MOVE,
        MOVE_TO_A,
        MOVING_TO_A,
        MOVE_TO_B,
        MOVING_TO_B
    }

    public void start() {
        configureShutDownHook();
        startAttackSimulationHosts();

        if (!waitForM3UALinks())
            return;

        this.printAttackSimulationStart();

        int sleepTime = 0,
                vipActionCounter = 0,
                vipTrackCounter = 0,
                vipInterceptCounter = 0,
                currentRuns = 0,
                hour_count = 100,
                week_count = hour_count * 24 * 7, // one week
                warmUpRuns = week_count * 3,
                maxRuns = week_count * 4,
                move_a_1 = (int)(hour_count * 8.1),
                move_a_2 = (int)(hour_count * 8.2),
                move_a_3 = (int)(hour_count * 8.3),
                move_a_4 = (int)(hour_count * 8.4),
                move_a_5 = (int)(hour_count * 8.5),
                move_b_1 = (int)(hour_count * 15.1),
                move_b_2 = (int)(hour_count * 15.2),
                move_b_3 = (int)(hour_count * 15.3),
                move_b_4 = (int)(hour_count * 15.4),
                move_b_5 = (int)(hour_count * 15.5);

        AttackSimulationOrganizer.VIP = this.getSubscriberManager().getVipSubscriber();

        boolean trafficGenerated, warmUpDone = false;
        VipNextAction vipNextAction = VipNextAction.FIRST_MOVE;

        IMSI vipImsi = VIP.getImsi();

        while (true) {
            if (currentRuns == maxRuns)
                currentRuns = 0;

            try {
                //sleepTime = AttackSimulationOrganizer.random.nextInt((1000 - 100) + 1) + 100;
                sleepTime = 800;

                if (this.testerHostsNeedQuit())
                    break;

                this.testerHostsExecuteCheckStore();

                if (simpleSimulation) {
                    switch (AttackSimulationOrganizer.simpleAttackGoal) {
                        case LOCATION_ATI:
                            this.attackLocationAti();
                            break;
                        case LOCATION_PSI:
                            this.attackLocationPsiDemo();
                            break;
                        case INTERCEPT_SMS:
                            this.attackInterceptSmsDemo();
                            break;
                        case TEST_PORTS:
                            break;
                    }
                    break;
                } else {
                    if (currentRuns < warmUpRuns) {
                        trafficGenerated = false;

                        switch(vipNextAction) {
                            case MOVE_TO_A:
                                if(vipActionCounter == 8 * hour_count)
                                    vipNextAction = VipNextAction.MOVING_TO_A;
                                break;
                            case MOVING_TO_A:
                                if (vipActionCounter == move_a_1) {
                                    vlrBhlrA.getTestAttackClient().performUpdateLocationRequest(vipImsi,
                                            AttackSimulationOrganizer.defaultMscBAddress,
                                            AttackSimulationOrganizer.defaultVlrBAddress,
                                            false,
                                            LAC_B_2);
                                    this.waitForUpdateLocationResponse(vlrBhlrA, true);
                                    vlrBhlrA.getTestAttackClient().clearLastUpdateLocationResponse();
                                    trafficGenerated = true;
                                } else if(vipActionCounter == move_a_2) {
                                    vlrBhlrA.getTestAttackClient().performUpdateLocationRequest(vipImsi,
                                            AttackSimulationOrganizer.defaultMscBAddress,
                                            AttackSimulationOrganizer.defaultVlrBAddress,
                                            false,
                                            LAC_B_1);
                                    this.waitForUpdateLocationResponse(vlrBhlrA, true);
                                    vlrBhlrA.getTestAttackClient().clearLastUpdateLocationResponse();
                                    trafficGenerated = true;
                                } else if(vipActionCounter == move_a_3) {
                                    vlrAhlrA.getTestAttackServer().performUpdateLocationRequest(vipImsi,
                                            AttackSimulationOrganizer.defaultMscAddress,
                                            AttackSimulationOrganizer.defaultVlrAddress,
                                            LAC_A_3);
                                    this.waitForUpdateLocationResponse(vlrAhlrA, false);
                                    vlrAhlrA.getTestAttackServer().clearLastUpdateLocationResponse();
                                    trafficGenerated = true;
                                } else if(vipActionCounter == move_a_4) {
                                    vlrAhlrA.getTestAttackServer().performUpdateLocationRequest(vipImsi,
                                            AttackSimulationOrganizer.defaultMscAddress,
                                            AttackSimulationOrganizer.defaultVlrAddress,
                                            LAC_A_2);
                                    this.waitForUpdateLocationResponse(vlrAhlrA, false);
                                    vlrAhlrA.getTestAttackServer().clearLastUpdateLocationResponse();
                                    trafficGenerated = true;
                                } else if(vipActionCounter == move_a_5) {
                                    vlrAhlrA.getTestAttackServer().performUpdateLocationRequest(vipImsi,
                                            AttackSimulationOrganizer.defaultMscAddress,
                                            AttackSimulationOrganizer.defaultVlrAddress,
                                            LAC_A_1);
                                    this.waitForUpdateLocationResponse(vlrAhlrA, false);
                                    vlrAhlrA.getTestAttackServer().clearLastUpdateLocationResponse();
                                    trafficGenerated = true;
                                    vipActionCounter = 0;
                                    vipNextAction = VipNextAction.MOVE_TO_B;
                                }
                                break;
                            case MOVE_TO_B:
                                if(vipActionCounter == 15 * hour_count)
                                    vipNextAction = VipNextAction.MOVING_TO_B;
                                break;
                            case MOVING_TO_B:
                                if(vipActionCounter == move_b_1) {
                                    vlrAhlrA.getTestAttackServer().performUpdateLocationRequest(vipImsi,
                                            AttackSimulationOrganizer.defaultMscAddress,
                                            AttackSimulationOrganizer.defaultVlrAddress,
                                            LAC_A_2);
                                    this.waitForUpdateLocationResponse(vlrAhlrA, false);
                                    vlrAhlrA.getTestAttackServer().clearLastUpdateLocationResponse();
                                    trafficGenerated = true;
                                } else if(vipActionCounter == move_b_2) {
                                    vlrAhlrA.getTestAttackServer().performUpdateLocationRequest(vipImsi,
                                            AttackSimulationOrganizer.defaultMscAddress,
                                            AttackSimulationOrganizer.defaultVlrAddress,
                                            LAC_A_3);
                                    this.waitForUpdateLocationResponse(vlrAhlrA, false);
                                    vlrAhlrA.getTestAttackServer().clearLastUpdateLocationResponse();
                                    trafficGenerated = true;
                                } else if(vipActionCounter == move_b_3) {
                                    vlrBhlrA.getTestAttackClient().performUpdateLocationRequest(vipImsi,
                                            AttackSimulationOrganizer.defaultMscBAddress,
                                            AttackSimulationOrganizer.defaultVlrBAddress,
                                            false,
                                            LAC_B_1);
                                    this.waitForUpdateLocationResponse(vlrBhlrA, true);
                                    vlrBhlrA.getTestAttackClient().clearLastUpdateLocationResponse();
                                    trafficGenerated = true;
                                } else if(vipActionCounter == move_b_4) {
                                    vlrBhlrA.getTestAttackClient().performUpdateLocationRequest(vipImsi,
                                            AttackSimulationOrganizer.defaultMscBAddress,
                                            AttackSimulationOrganizer.defaultVlrBAddress,
                                            false,
                                            LAC_B_2);
                                    this.waitForUpdateLocationResponse(vlrBhlrA, true);
                                    vlrBhlrA.getTestAttackClient().clearLastUpdateLocationResponse();
                                    trafficGenerated = true;
                                } else if(vipActionCounter == move_b_5) {
                                    vlrBhlrA.getTestAttackClient().performUpdateLocationRequest(vipImsi,
                                            AttackSimulationOrganizer.defaultMscBAddress,
                                            AttackSimulationOrganizer.defaultVlrBAddress,
                                            false,
                                            LAC_B_3);
                                    this.waitForUpdateLocationResponse(vlrBhlrA, true);
                                    vlrBhlrA.getTestAttackClient().clearLastUpdateLocationResponse();
                                    trafficGenerated = true;
                                    vipActionCounter = 0;
                                    vipNextAction = VipNextAction.MOVE_TO_A;
                                }
                                break;
                            case FIRST_MOVE:
                                if(vipActionCounter == (int)(8.5 * hour_count)) {
                                    vipActionCounter = (int)(14.99 * hour_count);
                                    trafficGenerated = false;
                                    vipNextAction = VipNextAction.MOVING_TO_B;
                                }
                                break;
                        }

                        if(!trafficGenerated) {
                            this.generateTraffic(true, VipAction.NONE);
                        }

                    } else {
                        trafficGenerated = false;

                        switch(vipNextAction) {
                            case MOVE_TO_A:
                                if(vipActionCounter == 8 * hour_count)
                                    vipNextAction = VipNextAction.MOVING_TO_A;
                                break;
                            case MOVING_TO_A:
                                if (vipActionCounter == move_a_1) {
                                    vlrBhlrA.getTestAttackClient().performUpdateLocationRequest(vipImsi,
                                            AttackSimulationOrganizer.defaultMscBAddress,
                                            AttackSimulationOrganizer.defaultVlrBAddress,
                                            false,
                                            LAC_B_2);
                                    this.waitForUpdateLocationResponse(vlrBhlrA, true);
                                    vlrBhlrA.getTestAttackClient().clearLastUpdateLocationResponse();
                                    trafficGenerated = true;
                                } else if(vipActionCounter == move_a_2) {
                                    vlrBhlrA.getTestAttackClient().performUpdateLocationRequest(vipImsi,
                                            AttackSimulationOrganizer.defaultMscBAddress,
                                            AttackSimulationOrganizer.defaultVlrBAddress,
                                            false,
                                            LAC_B_1);
                                    this.waitForUpdateLocationResponse(vlrBhlrA, true);
                                    vlrBhlrA.getTestAttackClient().clearLastUpdateLocationResponse();
                                    trafficGenerated = true;
                                } else if(vipActionCounter == move_a_3) {
                                    vlrAhlrA.getTestAttackServer().performUpdateLocationRequest(vipImsi,
                                            AttackSimulationOrganizer.defaultMscAddress,
                                            AttackSimulationOrganizer.defaultVlrAddress,
                                            LAC_A_3);
                                    this.waitForUpdateLocationResponse(vlrAhlrA, false);
                                    vlrAhlrA.getTestAttackServer().clearLastUpdateLocationResponse();
                                    trafficGenerated = true;
                                } else if(vipActionCounter == move_a_4) {
                                    vlrAhlrA.getTestAttackServer().performUpdateLocationRequest(vipImsi,
                                            AttackSimulationOrganizer.defaultMscAddress,
                                            AttackSimulationOrganizer.defaultVlrAddress,
                                            LAC_A_2);
                                    this.waitForUpdateLocationResponse(vlrAhlrA, false);
                                    vlrAhlrA.getTestAttackServer().clearLastUpdateLocationResponse();
                                    trafficGenerated = true;
                                } else if(vipActionCounter == move_a_5) {
                                    vlrAhlrA.getTestAttackServer().performUpdateLocationRequest(vipImsi,
                                            AttackSimulationOrganizer.defaultMscAddress,
                                            AttackSimulationOrganizer.defaultVlrAddress,
                                            LAC_A_1);
                                    this.waitForUpdateLocationResponse(vlrAhlrA, false);
                                    vlrAhlrA.getTestAttackServer().clearLastUpdateLocationResponse();
                                    trafficGenerated = true;
                                    vipActionCounter = 0;
                                    vipNextAction = VipNextAction.MOVE_TO_B;
                                }
                                break;
                            case MOVE_TO_B:
                                if(vipActionCounter == 15 * hour_count)
                                    vipNextAction = VipNextAction.MOVING_TO_B;
                                break;
                            case MOVING_TO_B:
                                if(vipActionCounter == move_b_1) {
                                    vlrAhlrA.getTestAttackServer().performUpdateLocationRequest(vipImsi,
                                            AttackSimulationOrganizer.defaultMscAddress,
                                            AttackSimulationOrganizer.defaultVlrAddress,
                                            LAC_A_2);
                                    this.waitForUpdateLocationResponse(vlrAhlrA, false);
                                    vlrAhlrA.getTestAttackServer().clearLastUpdateLocationResponse();
                                    trafficGenerated = true;
                                } else if(vipActionCounter == move_b_2) {
                                    vlrAhlrA.getTestAttackServer().performUpdateLocationRequest(vipImsi,
                                            AttackSimulationOrganizer.defaultMscAddress,
                                            AttackSimulationOrganizer.defaultVlrAddress,
                                            LAC_A_3);
                                    this.waitForUpdateLocationResponse(vlrAhlrA, false);
                                    vlrAhlrA.getTestAttackServer().clearLastUpdateLocationResponse();
                                    trafficGenerated = true;
                                } else if(vipActionCounter == move_b_3) {
                                    vlrBhlrA.getTestAttackClient().performUpdateLocationRequest(vipImsi,
                                            AttackSimulationOrganizer.defaultMscBAddress,
                                            AttackSimulationOrganizer.defaultVlrBAddress,
                                            false,
                                            LAC_B_1);
                                    this.waitForUpdateLocationResponse(vlrBhlrA, true);
                                    vlrBhlrA.getTestAttackClient().clearLastUpdateLocationResponse();
                                    trafficGenerated = true;
                                } else if(vipActionCounter == move_b_4) {
                                    vlrBhlrA.getTestAttackClient().performUpdateLocationRequest(vipImsi,
                                            AttackSimulationOrganizer.defaultMscBAddress,
                                            AttackSimulationOrganizer.defaultVlrBAddress,
                                            false,
                                            LAC_B_2);
                                    this.waitForUpdateLocationResponse(vlrBhlrA, true);
                                    vlrBhlrA.getTestAttackClient().clearLastUpdateLocationResponse();
                                    trafficGenerated = true;
                                } else if(vipActionCounter == move_b_5) {
                                    vlrBhlrA.getTestAttackClient().performUpdateLocationRequest(vipImsi,
                                            AttackSimulationOrganizer.defaultMscBAddress,
                                            AttackSimulationOrganizer.defaultVlrBAddress,
                                            false,
                                            LAC_B_3);
                                    this.waitForUpdateLocationResponse(vlrBhlrA, true);
                                    vlrBhlrA.getTestAttackClient().clearLastUpdateLocationResponse();
                                    trafficGenerated = true;
                                    vipActionCounter = 0;
                                    vipNextAction = VipNextAction.MOVE_TO_A;
                                }
                                break;
                        }

                        if(vipInterceptCounter == 10 * hour_count) {
                            this.generateTraffic(false, VipAction.INTERCEPT);
                            vipInterceptCounter = 0;
                            trafficGenerated = true;
                        }

                        if(vipTrackCounter == hour_count) {
                            this.generateTraffic(false, VipAction.TRACK);
                            vipTrackCounter = 0;
                            trafficGenerated = true;
                        }

                        if(!trafficGenerated) {
                            this.generateTraffic(true, VipAction.NONE);
                        }


                        vipTrackCounter++;
                        vipInterceptCounter++;
                    }

                    vipActionCounter++;
                    currentRuns++;
                }


                Thread.sleep(sleepTime);
            }
            catch (InterruptedException e) {
                e.printStackTrace();
                break;
            }
        }
    }

    private void generateTraffic(boolean noise, VipAction vipAction) {
        if(noise) {
            countGenuineProcedures++;
            this.sendRandomMessage();
        } else {
            switch (vipAction) {
                case NONE:
                    break;
                case TRACK:
                    countAttackProcedures++;
                    this.attackLocationPsi();
                    break;
                case INTERCEPT:
                    countAttackProcedures++;
                    this.attackInterceptSms();
                    break;
            }
        }
    }

    private void generateAttack() {
        int numberOfAttacks = 4;
        int randomAttack = AttackSimulationOrganizer.random.nextInt(numberOfAttacks);

        switch(randomAttack) {
            case 0:
                printSentMessage("Location:AnyTimeInterrogation", false);
                this.attackLocationAti();
                break;
            case 1:
                printSentMessage("Location:ProvideSubscriberInfo", false);
                this.attackLocationPsi();
                break;
            case 2:
                printSentMessage("Intercept:SMS", false);
                this.attackInterceptSms();
                break;
            case 3:
                printSentMessage("Scan:SRIForSM", false);
                this.attackScanSRIForSM();
                break;
        }
    }

    private void sendRandomIsupMessage(int num) {
        switch(num) {
            case 0:
                this.isupClient.getTestAttackClient().performIsupIAM();
        }
    }

    private void sendRandomMessage() {
        int numberOfAvailableMessages = 13;
        int randomMessage = AttackSimulationOrganizer.random.nextInt(numberOfAvailableMessages);

        switch (randomMessage) {
            case 0:
                printSentMessage("MoForwardSMS", true);
                this.performShortMessageMobileOriginated();
                break;
            case 1:
                printSentMessage("MtForwardSMS", true);
                this.performShortMessageMobileTerminated();
                break;
            case 2:
                printSentMessage("PurgeMS", true);
                this.performPurgeMS();
                break;
            case 3:
                printSentMessage("DeleteSubscriberData", true);
                this.performDeleteSubscriberData();
                break;
            case 4:
                printSentMessage("AnyTimeInterrogation", true);
                this.performAnyTimeInterrogation();
                break;
            case 5:
                printSentMessage("ActivateTraceMode_Oam", true);
                this.performActivateTraceMode_Oam();
                break;
            case 6:
                printSentMessage("SendIMSI", true);
                this.performSendIMSI();
                break;
            case 7:
                printSentMessage("RetrieveRoutingInformationProcedure", true);
                this.performRetrieveRoutingInformationProcedure();
                break;
            case 8:
                printSentMessage("RegistrationProcedure", true);
                this.performRegistrationProcedure();
                break;
            case 9:
                printSentMessage("ErasureProcedure", true);
                this.performErasureProcedure();
                break;
            case 10:
                printSentMessage("ShortMessageAlertProcedure", true);
                this.performShortMessageAlertProcedure();
                break;
            case 11:
                printSentMessage("SendRoutingInfoForGPRS", true);
                this.performSendRoutingInfoForGPRS();
                break;
            case 12:
                printSentMessage("LocationUpdate", true);
                this.performLocationUpdate();
                break;

            default:
                break;
        }
    }

    private void attackLocationAti() {
        AttackSimulationOrganizer.attackerBhlrA.getTestAttackClient().performATI(VIP.getMsisdn().getAddress());
    }

    private void attackLocationPsiDemo() {
        AttackSimulationOrganizer.attackerBhlrA.getTestAttackClient().performSendRoutingInfoForSM(VIP.getMsisdn().getAddress(),
                AttackSimulationOrganizer.hlrAattackerB.getTestAttackServer().getServiceCenterAddress());
        this.waitForSRIForSMResponse(AttackSimulationOrganizer.attackerBhlrA);

        SendRoutingInfoForSMResponse sriResponse = AttackSimulationOrganizer.attackerBhlrA.getTestAttackClient().getLastSRIForSMResponse();
        AttackSimulationOrganizer.attackerBhlrA.getTestAttackClient().clearLastSRIForSMResponse();

        IMSI victimImsi = sriResponse.getIMSI();
        String victimVlrAddress = sriResponse.getLocationInfoWithLMSI().getNetworkNodeNumber().getAddress();

        AttackSimulationOrganizer.attackerBvlrA.getConfigurationData().getMapConfigurationData().setRemoteAddressDigits(victimVlrAddress);
        AttackSimulationOrganizer.attackerBvlrA.getTestAttackClient().performProvideSubscriberInfoRequest(VIP.getImsi());

        this.waitForPSIResponse(AttackSimulationOrganizer.attackerBvlrA, true);

        ProvideSubscriberInfoResponse psiResponse = AttackSimulationOrganizer.attackerBvlrA.getTestAttackClient().getLastPsiResponse();
        AttackSimulationOrganizer.attackerBvlrA.getTestAttackClient().clearLastPsiResponse();
    }

    private void attackLocationPsi() {
        AttackSimulationOrganizer.attackerBvlrA.getTestAttackClient().performProvideSubscriberInfoRequest(VIP.getImsi());

        this.waitForPSIResponse(AttackSimulationOrganizer.attackerBvlrA, true);

        ProvideSubscriberInfoResponse psiResponse = AttackSimulationOrganizer.attackerBvlrA.getTestAttackClient().getLastPsiResponse();
        AttackSimulationOrganizer.attackerBvlrA.getTestAttackClient().clearLastPsiResponse();
    }

    private void attackInterceptSms() {
        MAPParameterFactory mapParameterFactory = AttackSimulationOrganizer.attackerBhlrA.getMapMan().getMAPStack().getMAPProvider().getMAPParameterFactory();

        ISDNAddressString newMscAddress = mapParameterFactory.createISDNAddressString(
                AttackSimulationOrganizer.attackerBhlrA.getConfigurationData().getTestAttackClientConfigurationData().getAddressNature(),
                AttackSimulationOrganizer.attackerBhlrA.getConfigurationData().getTestAttackClientConfigurationData().getNumberingPlan(),
                AttackSimulationOrganizer.attackerBhlrA.getConfigurationData().getSccpConfigurationData().getCallingPartyAddressDigits());
        ISDNAddressString newVlrAddress = mapParameterFactory.createISDNAddressString(
                AttackSimulationOrganizer.attackerBhlrA.getConfigurationData().getTestAttackClientConfigurationData().getAddressNature(),
                AttackSimulationOrganizer.attackerBhlrA.getConfigurationData().getTestAttackClientConfigurationData().getNumberingPlan(),
                AttackSimulationOrganizer.attackerBhlrA.getConfigurationData().getSccpConfigurationData().getCallingPartyAddressDigits());

        AttackSimulationOrganizer.attackerBhlrA.getTestAttackClient().performUpdateLocationRequest(VIP.getImsi(), newMscAddress, newVlrAddress, true, LAC_C_1);
        this.waitForUpdateLocationResponse(attackerBhlrA, true);
        attackerBhlrA.getTestAttackClient().clearLastUpdateLocationResponse();
    }

    private void attackInterceptSmsDemo() {
        MAPParameterFactory mapParameterFactory = AttackSimulationOrganizer.attackerBhlrA.getMapMan().getMAPStack().getMAPProvider().getMAPParameterFactory();

        AttackSimulationOrganizer.smscAhlrA.getTestAttackClient().performSendRoutingInfoForSM(VIP.getMsisdn().getAddress(), AttackSimulationOrganizer.hlrAsmscA.getConfigurationData().getTestAttackServerConfigurationData().getServiceCenterAddress());
        this.waitForSRIForSMResponse(AttackSimulationOrganizer.smscAhlrA);

        SendRoutingInfoForSMResponse sriResponse = AttackSimulationOrganizer.smscAhlrA.getTestAttackClient().getLastSRIForSMResponse();
        AttackSimulationOrganizer.smscAhlrA.getTestAttackClient().clearLastSRIForSMResponse();
        AttackSimulationOrganizer.smscAmscA.getTestAttackServer().performMtForwardSM("SMS Message", sriResponse.getIMSI(),
                sriResponse.getLocationInfoWithLMSI().getNetworkNodeNumber().getAddress(),
                this.getSubscriberManager().getRandomSubscriber().getMsisdn().getAddress(),
                AttackSimulationOrganizer.defaultSmscAddress.getAddress());

        try {
            Thread.sleep(2000);
        } catch(InterruptedException e) {
            System.exit(50);
        }

        AttackSimulationOrganizer.attackerBhlrA.getTestAttackClient().performSendRoutingInfoForSM(VIP.getMsisdn().getAddress(), AttackSimulationOrganizer.hlrAsmscA.getConfigurationData().getTestAttackServerConfigurationData().getServiceCenterAddress());
        this.waitForSRIForSMResponse(AttackSimulationOrganizer.attackerBhlrA);

        sriResponse = AttackSimulationOrganizer.attackerBhlrA.getTestAttackClient().getLastSRIForSMResponse();
        AttackSimulationOrganizer.attackerBhlrA.getTestAttackClient().clearLastSRIForSMResponse();

        ISDNAddressString newMscAddress = mapParameterFactory.createISDNAddressString(
                AttackSimulationOrganizer.attackerBhlrA.getConfigurationData().getTestAttackClientConfigurationData().getAddressNature(),
                AttackSimulationOrganizer.attackerBhlrA.getConfigurationData().getTestAttackClientConfigurationData().getNumberingPlan(),
                AttackSimulationOrganizer.OPERATOR_C_GT);
        ISDNAddressString newVlrAddress = mapParameterFactory.createISDNAddressString(
                AttackSimulationOrganizer.attackerBhlrA.getConfigurationData().getTestAttackClientConfigurationData().getAddressNature(),
                AttackSimulationOrganizer.attackerBhlrA.getConfigurationData().getTestAttackClientConfigurationData().getNumberingPlan(),
                AttackSimulationOrganizer.OPERATOR_C_GT);

        AttackSimulationOrganizer.attackerBhlrA.getTestAttackClient().performUpdateLocationRequest(sriResponse.getIMSI(), newMscAddress, newVlrAddress, true, LAC_C_1);
        this.waitForUpdateLocationResponse(AttackSimulationOrganizer.attackerBhlrA, true);
        AttackSimulationOrganizer.attackerBhlrA.getTestAttackClient().clearLastUpdateLocationResponse();

        AttackSimulationOrganizer.smscAhlrA.getTestAttackClient().performSendRoutingInfoForSM(VIP.getMsisdn().getAddress(), AttackSimulationOrganizer.hlrAsmscA.getConfigurationData().getTestAttackServerConfigurationData().getServiceCenterAddress());
        this.waitForSRIForSMResponse(AttackSimulationOrganizer.smscAhlrA);

        sriResponse = AttackSimulationOrganizer.smscAhlrA.getTestAttackClient().getLastSRIForSMResponse();
        AttackSimulationOrganizer.smscAhlrA.getTestAttackClient().clearLastSRIForSMResponse();
        AttackSimulationOrganizer.smscAattackerB.getTestAttackServer().performMtForwardSM(DEFAULT_SMS_MESSAGE, sriResponse.getIMSI(),
                sriResponse.getLocationInfoWithLMSI().getNetworkNodeNumber().getAddress(),
                this.getSubscriberManager().getRandomSubscriber().getMsisdn().getAddress(),
                AttackSimulationOrganizer.defaultSmscAddress.getAddress());
    }

    public void attackScanSRIForSM() {
        int numberOfScans;
        ArrayList<Subscriber> scanTargets = new ArrayList<Subscriber>();

        if(this.getSubscriberManager().getNumberOfSubscribers() > 10)
            numberOfScans = AttackSimulationOrganizer.random.nextInt(10);
        else
            numberOfScans = AttackSimulationOrganizer.random.nextInt(this.getSubscriberManager().getNumberOfSubscribers());

        for(int i = 0; i < numberOfScans; i++)
            scanTargets.add(this.getSubscriberManager().getRandomSubscriber());

        for(Subscriber scanTarget : scanTargets) {
            AttackSimulationOrganizer.attackerBhlrA.getTestAttackClient().performSendRoutingInfoForSM(
                    scanTarget.getMsisdn().getAddress(), this.getDefaultSmscAddress().getAddress());
            this.waitForSRIForSMResponse(AttackSimulationOrganizer.attackerBhlrA);
            AttackSimulationOrganizer.attackerBhlrA.getTestAttackClient().clearLastSRIForSMResponse();
        }
    }

    public void waitForUpdateLocationResponse(AttackTesterHost node, boolean client) {
        while(!node.gotUpdateLocationResponse(client)) {
            try{
                Thread.sleep(50);
            } catch(InterruptedException e) {
                System.exit(50);
            }
        }
    }

    public void waitForSRIForSMResponse(AttackTesterHost node) {
        while(!node.gotSRIForSMResponse()) {
            try {
                Thread.sleep(50);
            } catch(InterruptedException e) {
                System.exit(50);
            }
        }
    }

    public void waitForMtForwardSMResponse(AttackTesterHost node, boolean client) {
        int tries = 0;
        while(!node.gotMtForwardSMResponse(client)) {
            try {
                if(tries < 100) {
                    Thread.sleep(50);
                    tries++;
                } else {
                    break;
                }
            } catch(InterruptedException e) {
                System.exit(50);
            }
        }
    }

    public void waitForProvideRoamingNumberResponse(AttackTesterHost node, boolean client) {
        int tries = 0;
        while(!node.gotProvideRoamingNumberResponse(client)) {
            try {
                if(tries < 100) {
                    Thread.sleep(50);
                    tries++;
                } else {
                    break;
                }
            } catch(InterruptedException e) {
                System.exit(50);
            }
        }
    }

    public void waitForPSIResponse(AttackTesterHost node, boolean client) {
        int tries = 0;
        while(!node.gotPSIResponse(client)) {
            try {
                if(tries < 100) {
                    Thread.sleep(50);
                    tries++;
                } else {
                    break;
                }
            } catch(InterruptedException e) {
                System.exit(50);
            }
        }
    }

    public void waitForRegisterSSResponse(AttackTesterHost node, boolean client) {
        int tries = 0;
        while(!node.gotRegisterSSResponse(client)) {
            try {
                if(tries < 100) {
                    Thread.sleep(50);
                    tries++;
                } else {
                    break;
                }
            } catch(InterruptedException e) {
                System.exit(50);
            }
        }
    }

    public void waitForEraseSSResponse(AttackTesterHost node, boolean client) {
        int tries = 0;
        while(!node.gotEraseSSResponse(client)) {
            try {
                if(tries < 100) {
                    Thread.sleep(50);
                    tries++;
                } else {
                    break;
                }
            } catch(InterruptedException e) {
                System.exit(50);
            }
        }
    }

    public void waitForSendRoutingInfoResponse(AttackTesterHost node) {
        int tries = 0;
        while(!node.gotSendRoutingInfoResponse()) {
            try {
                if(tries < 100) {
                    Thread.sleep(50);
                    tries++;
                } else {
                    break;
                }
            } catch(InterruptedException e) {
                System.exit(50);
            }
        }
    }

    public void waitForInsertSubscriberDataResponse(AttackTesterHost node, boolean client) {
        int tries = 0;
        while(!node.gotInsertSubscriberDataResponse(client)) {
            try {
                if(tries < 100) {
                    Thread.sleep(50);
                    tries++;
                } else {
                    break;
                }
            } catch(InterruptedException e) {
                System.exit(50);
            }
        }
    }

    public void waitForCancelLocationResponse(AttackTesterHost node, boolean client) {
        int tries = 0;
        while(!node.gotCancelLocationResponse(client)) {
            try {
                if(tries < 100) {
                    Thread.sleep(50);
                    tries++;
                } else {
                    break;
                }
            } catch(InterruptedException e) {
                System.exit(50);
            }
        }
    }

    public void waitForActivateTraceModeResponse(AttackTesterHost node, boolean client) {
        int tries = 0;
        while(!node.gotActivateTraceModeResponse(client)) {
            try {
                if(tries < 100) {
                    Thread.sleep(50);
                    tries++;
                } else {
                    break;
                }
            } catch(InterruptedException e) {
                System.exit(50);
            }
        }
    }

    private void performShortMessageMobileOriginated() {
        /**
         * Process per 3GPP TS 23.040 section 10.2:
         * MSC/SGSN             SMSC                         HLR                         MSC/SGSN
         *  |---MoForwardSMReq--->|--------SRIForSMReq------->|                              |
         *  |                     |<-------SrIForSMResp-------|                              |
         *  |                     |-----------------MtForwardShortMessageReq---------------->|
         *  |<--MoForwardSMResp---|<----------------MtForwardShortMessageResp----------------|
        */

        boolean destinationOperatorA = AttackSimulationOrganizer.random.nextBoolean();

        Subscriber originator = AttackSimulationOrganizer.subscriberManager.getRandomSubscriber();
        Subscriber destination = AttackSimulationOrganizer.subscriberManager.getRandomSubscriber();

        String origIsdnNumber = originator.getMsisdn().getAddress();
        String destIsdnNumber = destination.getMsisdn().getAddress();
        String scAddr = this.getDefaultSmscAddress().getAddress();

        AttackSimulationOrganizer.mscAsmscA.getTestAttackClient().performMoForwardSM(DEFAULT_SMS_MESSAGE, destIsdnNumber, origIsdnNumber, scAddr);
    }

    private void performShortMessageMobileTerminated() {
        /**
         * Process per 3GPP TS 23.040 section 10.1:
         *  SMSC              SMSC                         HLR                         MSC/SGSN
         *    |-MtForwardSMReq->|--------SRIForSMReq------->|                              |
         *    |                 |<-------SrIForSMResp-------|                              |
         *    |                 |-----------------MtForwardShortMessageReq---------------->|
         *    |                 |<----------------MtForwardShortMessageResp----------------|
         *    |                 |----ReportSMDeliveryReq--->|
         */

        Subscriber originator = AttackSimulationOrganizer.subscriberManager.getRandomSubscriber();
        Subscriber destination = AttackSimulationOrganizer.subscriberManager.getRandomSubscriber();

        String destIsdnNumber = destination.getMsisdn().getAddress();

        if(originator.getCurrentMscNumber().equals(AttackSimulationOrganizer.defaultMscAddress)) { //Message originates from A
            AttackSimulationOrganizer.smscAhlrA.getTestAttackClient().performSendRoutingInfoForSM(destIsdnNumber,
                    hlrAsmscA.getConfigurationData().getSccpConfigurationData().getCallingPartyAddressDigits());
            this.waitForSRIForSMResponse(AttackSimulationOrganizer.smscAhlrA);
            SendRoutingInfoForSMResponse sriResponse = AttackSimulationOrganizer.smscAhlrA.getTestAttackClient().getLastSRIForSMResponse();
            AttackSimulationOrganizer.smscAhlrA.getTestAttackClient().clearLastSRIForSMResponse();

            if(destination.getCurrentMscNumber().equals(AttackSimulationOrganizer.defaultMscAddress)) { //Destination is A
                AttackSimulationOrganizer.smscAmscA.getTestAttackServer().performMtForwardSM(DEFAULT_SMS_MESSAGE, sriResponse.getIMSI(),
                        sriResponse.getLocationInfoWithLMSI().getNetworkNodeNumber().getAddress(), originator.getMsisdn().getAddress(),
                        this.getDefaultSmscAddress().getAddress());
                this.waitForMtForwardSMResponse(AttackSimulationOrganizer.smscAmscA, false);
                AttackSimulationOrganizer.smscAmscA.getTestAttackServer().clearLastMtForwardSMResponse();

                AttackSimulationOrganizer.smscAhlrA.getTestAttackClient().performReportSMDeliveryStatus(destination.getMsisdn());

            } else if(destination.getCurrentMscNumber().equals(AttackSimulationOrganizer.defaultMscBAddress)) { //Destination is B
                AttackSimulationOrganizer.smscAsmscB.getTestAttackServer().performMtForwardSM(DEFAULT_SMS_MESSAGE, sriResponse.getIMSI(),
                        sriResponse.getLocationInfoWithLMSI().getNetworkNodeNumber().getAddress(), originator.getMsisdn().getAddress(),
                        this.getDefaultSmscAddress().getAddress());
                this.waitForMtForwardSMResponse(AttackSimulationOrganizer.smscAsmscB, false);
                AttackSimulationOrganizer.smscAsmscB.getTestAttackServer().clearLastMtForwardSMResponse();

                AttackSimulationOrganizer.smscBhlrA.getTestAttackClient().performReportSMDeliveryStatus(destination.getMsisdn());

            } else { //Destination is Attacker
                AttackSimulationOrganizer.smscAattackerB.getTestAttackServer().performMtForwardSM(DEFAULT_SMS_MESSAGE, sriResponse.getIMSI(),
                        sriResponse.getLocationInfoWithLMSI().getNetworkNodeNumber().getAddress(), originator.getMsisdn().getAddress(),
                        this.getDefaultSmscAddress().getAddress());
                this.waitForMtForwardSMResponse(AttackSimulationOrganizer.smscAattackerB, false);
                AttackSimulationOrganizer.smscAattackerB.getTestAttackServer().clearLastMtForwardSMResponse();
            }
        } else { //Message originates from B
            if(destination.getCurrentMscNumber().equals(AttackSimulationOrganizer.defaultMscAddress)) { //Destination is A
                AttackSimulationOrganizer.smscBhlrA.getTestAttackClient().performSendRoutingInfoForSM(destIsdnNumber,
                        hlrAsmscB.getConfigurationData().getSccpConfigurationData().getCallingPartyAddressDigits());
                this.waitForSRIForSMResponse(AttackSimulationOrganizer.smscBhlrA);
                SendRoutingInfoForSMResponse sriResponse = AttackSimulationOrganizer.smscBhlrA.getTestAttackClient().getLastSRIForSMResponse();
                AttackSimulationOrganizer.smscBhlrA.getTestAttackClient().clearLastSRIForSMResponse();

                AttackSimulationOrganizer.smscBsmscA.getTestAttackClient().performMtForwardSM(DEFAULT_SMS_MESSAGE, sriResponse.getIMSI(),
                        sriResponse.getLocationInfoWithLMSI().getNetworkNodeNumber().getAddress(), originator.getMsisdn().getAddress(),
                        this.getDefaultSmscBAddress().getAddress());
                this.waitForMtForwardSMResponse(AttackSimulationOrganizer.smscBsmscA, true);
                AttackSimulationOrganizer.smscBsmscA.getTestAttackClient().clearLastMtForwardSMResponse();

                AttackSimulationOrganizer.smscAhlrA.getTestAttackClient().performSendRoutingInfoForSM(destIsdnNumber,
                        hlrAsmscA.getConfigurationData().getSccpConfigurationData().getCallingPartyAddressDigits());
                this.waitForSRIForSMResponse(AttackSimulationOrganizer.smscAhlrA);
                sriResponse = AttackSimulationOrganizer.smscAhlrA.getTestAttackClient().getLastSRIForSMResponse();
                AttackSimulationOrganizer.smscAhlrA.getTestAttackClient().clearLastSRIForSMResponse();

                AttackSimulationOrganizer.smscAmscA.getTestAttackServer().performMtForwardSM(DEFAULT_SMS_MESSAGE, sriResponse.getIMSI(),
                        sriResponse.getLocationInfoWithLMSI().getNetworkNodeNumber().getAddress(), originator.getMsisdn().getAddress(),
                        this.getDefaultSmscAddress().getAddress());
                this.waitForMtForwardSMResponse(AttackSimulationOrganizer.smscAmscA, false);
                AttackSimulationOrganizer.smscAmscA.getTestAttackServer().clearLastMtForwardSMResponse();

                AttackSimulationOrganizer.smscAhlrB.getTestAttackServer().performReportSMDeliveryStatus(destination.getMsisdn());
            }
        }


    }

    private void performShortMessageAlertProcedure() {
        /**
         * Process per 3GPP TS 23.040 section 10.3:
         * Mobile is present:
         * VLR/SGSN                    HLR                           SMSC
         *    |-----ReadyForSMReq/----->|----AlertServiceCentreReq--->|
         *    |----UpdateLocationReq--->|                             |
         *    |<----ReadyForSMResp------|                             |
         *    |                         |<---AlertServiceCentreResp---|
         *
         * MS memory capacity available:
         * MSC/SGSN                    VLR                           HLR                           SMSC
         *    |-----ReadyForSMReq------>|--------ReadyForSMReq------->|----AlertServiceCentreReq--->|
         *    |<----ReadyForSMResp------|<------ReadyForSMResp--------|                             |
         *    |                         |                             |<---AlertServiceCentreResp---|
         *
         */

        Subscriber subscriber = this.getSubscriberManager().getRandomSubscriber();

        int origin = AttackSimulationOrganizer.random.nextInt(3);

        switch(origin) {
            //Operator A internal procedure.
            case 0:
                AttackSimulationOrganizer.vlrAhlrA.getTestAttackServer().performReadyForSM(subscriber.getImsi());
                AttackSimulationOrganizer.hlrAsmscA.getTestAttackServer().performAlertServiceCentre(subscriber.getMsisdn(), AttackSimulationOrganizer.defaultSmscAddress.getAddress());
                break;
            //Subscriber from B is located in A.
            case 1:
                AttackSimulationOrganizer.vlrAhlrB.getTestAttackServer().performReadyForSM(subscriber.getImsi());
                AttackSimulationOrganizer.hlrBsmscA.getTestAttackClient().performAlertServiceCentre(subscriber.getMsisdn(), AttackSimulationOrganizer.defaultSmscAddress.getAddress());
                break;
            //Subscriber from A is located in B.
            case 2:
                AttackSimulationOrganizer.vlrBhlrA.getTestAttackClient().performReadyForSM(subscriber.getImsi());
                AttackSimulationOrganizer.hlrAsmscB.getTestAttackServer().performAlertServiceCentre(subscriber.getMsisdn(), AttackSimulationOrganizer.defaultSmscBAddress.getAddress());
                break;
        }
    }

    private void performLocationUpdate() {
        /**
         * Process per 3GPP TS 29.002 section 19.1.1:
         * MSC/VLR                       PVLR                           HLR
         *    |--------------------UpdateLocationReq-------------------->|
         *    |                            |<-----CancelLocationReq------|
         *    |                            |------CancelLocationResp---->|
         *    |<-----------------ActivateTraceModeReq--------------------|
         *    |------------------ActivateTraceModeResp------------------>|
         *    |<----------------InsertSubscriberDataReq------------------|
         *    |-----------------InsertSubscriberDataResp---------------->|
         *    |<-------------------UpdateLocationResp--------------------|
         */

        Subscriber subscriber = this.getSubscriberManager().getRandomSubscriber();
            while(subscriber.getSubscriberId() == 0) //Do not alter location of VIP unless specified.
                subscriber = this.getSubscriberManager().getRandomSubscriber();

        boolean subscriberIsInA = subscriber.getCurrentMscNumber().equals(AttackSimulationOrganizer.defaultMscAddress);
        int newLAC = 0;

        if(subscriber.isOperatorAHome()) {
            //Move to B
            if(subscriberIsInA) {
                switch(random.nextInt(3)) {
                    case 0:
                        newLAC = LAC_B_1;
                        break;
                    case 1:
                        newLAC = LAC_B_2;
                        break;
                    case 2:
                        newLAC = LAC_B_3;
                        break;
                }
                AttackSimulationOrganizer.vlrBhlrA.getTestAttackClient().performUpdateLocationRequest(subscriber.getImsi(), AttackSimulationOrganizer.defaultMscBAddress, AttackSimulationOrganizer.defaultVlrBAddress, false, newLAC);
            //Move to A
            } else {
                switch(random.nextInt(3)) {
                    case 0:
                        newLAC = LAC_A_1;
                        break;
                    case 1:
                        newLAC = LAC_A_2;
                        break;
                    case 2:
                        newLAC = LAC_A_3;
                        break;
                }
                AttackSimulationOrganizer.vlrAhlrA.getTestAttackServer().performUpdateLocationRequest(subscriber.getImsi(), AttackSimulationOrganizer.defaultMscAddress, AttackSimulationOrganizer.defaultVlrAddress, newLAC);
            }
        } else {
            //Move to A
            if(!subscriberIsInA) {
                switch(random.nextInt(3)) {
                    case 0:
                        newLAC = LAC_A_1;
                        break;
                    case 1:
                        newLAC = LAC_A_2;
                        break;
                    case 2:
                        newLAC = LAC_A_3;
                        break;
                }
                AttackSimulationOrganizer.vlrAhlrB.getTestAttackServer().performUpdateLocationRequest(subscriber.getImsi(), AttackSimulationOrganizer.defaultMscAddress, AttackSimulationOrganizer.defaultVlrAddress, newLAC);
            }
        }
    }

    private void performSendIdentification() {
        //this.vlrAvlrB.getTestAttackClient().performSendIdentification();
        //this.vlrBvlrA.getTestAttackServer().performSendIdentification();
    }

    private void performPurgeMS() {
        Subscriber subscriber = this.getSubscriberManager().getRandomSubscriber();

        if(subscriber.isOperatorAHome()) {
            if(subscriber.getCurrentMscNumber().equals(AttackSimulationOrganizer.defaultMscAddress))
                AttackSimulationOrganizer.vlrAhlrA.getTestAttackServer().performPurgeMS(subscriber.getImsi(), subscriber.getCurrentVlrNumber());
            else
                AttackSimulationOrganizer.vlrBhlrA.getTestAttackClient().performPurgeMS(subscriber.getImsi(), subscriber.getCurrentVlrNumber());
        } else {
            AttackSimulationOrganizer.vlrAhlrB.getTestAttackServer().performPurgeMS(subscriber.getImsi(), subscriber.getCurrentVlrNumber());
        }
    }

    private void performUpdateGPRSLocation() {
        //this.sgsnAhlrA.getTestAttackClient().performUpdateGPRSLocation();
    }

    private void performCheckIMEI() {
        //this.mscAeirA.getTestAttackClient().performCheckIMEI();
        //this.sgsnAeirA.getTestAttackClient().performCheckIMEI();
    }

    private void performDeleteSubscriberData() {
        Subscriber subscriber = this.getSubscriberManager().getRandomSubscriber();
        AttackSimulationOrganizer.hlrAvlrA.getTestAttackClient().performDeleteSubscriberData(subscriber.getImsi());
    }

    private void performForwardCheckSSIndication() {
        //this.hlrAmscA.getTestAttackServer().performForwardCheckSSIndication();
    }

    private void performAnyTimeInterrogation() {
        Subscriber subscriber = this.getSubscriberManager().getRandomSubscriber();
        AttackSimulationOrganizer.gsmscfAhlrA.getTestAttackClient().performATI(subscriber.getMsisdn().getAddress());
    }

    private void performActivateTraceMode_Oam() {
        Subscriber subscriber = this.getSubscriberManager().getRandomSubscriber();
        AttackSimulationOrganizer.hlrAvlrA.getTestAttackClient().performActivateTraceMode_Oam(subscriber.getImsi());
    }

    private void performSendIMSI() {
        Subscriber subscriber = this.getSubscriberManager().getRandomSubscriber();
        AttackSimulationOrganizer.vlrAhlrA.getTestAttackServer().performSendIMSI(subscriber.getMsisdn());
    }

    private void performRetrieveRoutingInformationProcedure() {
        /**
         * Process per 3GPP TS 29.002 21.2:
         * MSC                           HLR                                      VLR
         *  |-----SendRoutingInfoReq----->|--------ProvideRoamingNumberReq-------->|
         *  |<----SendRoutingInfoResp-----|<-------ProvideRoamingNumberResp--------|
         *  |                             |<------------RestoreDataReq-------------|
         *  |                             |--------InsertSubscriberDataReq-------->|
         *  |                             |<-------InsertSubscriberDataResp--------|
         *  |                             |-------------RestoreDataResp----------->|
         */
        Subscriber subscriber = this.getSubscriberManager().getRandomSubscriber();
        boolean subscriberInA = subscriber.getCurrentMscNumber().equals(AttackSimulationOrganizer.defaultMscAddress);

        if(subscriber.isOperatorAHome()) {
            if(subscriberInA) {
                AttackSimulationOrganizer.mscAhlrA.getTestAttackClient().performSendRoutingInformation(subscriber.getMsisdn());
                this.waitForSendRoutingInfoResponse(AttackSimulationOrganizer.mscAhlrA);
                AttackSimulationOrganizer.vlrAhlrA.getTestAttackServer().performRestoreData(subscriber.getImsi());
            } else {
                AttackSimulationOrganizer.mscBhlrA.getTestAttackClient().performSendRoutingInformation(subscriber.getMsisdn());
                this.waitForSendRoutingInfoResponse(AttackSimulationOrganizer.mscBhlrA);
                AttackSimulationOrganizer.vlrBhlrA.getTestAttackClient().performRestoreData(subscriber.getImsi());
            }
        } else {
            if(subscriberInA) {
                AttackSimulationOrganizer.hlrBvlrA.getTestAttackClient().performProvideRoamingNumber(subscriber.getImsi(), subscriber.getCurrentMscNumber());
                this.waitForProvideRoamingNumberResponse(AttackSimulationOrganizer.hlrBvlrA, true);
                AttackSimulationOrganizer.vlrAhlrB.getTestAttackServer().performRestoreData(subscriber.getImsi());
            }
        }
    }

    private void performRegistrationProcedure() {
        /**
         * Category 3 message, is used between operator networks.
         *
         * Process per standard 22.2:
         * MSC                  VLR                           HLR
         *  |---RegisterSSReq--->|--------RegisterSSReq------->|
         *  |<--RegisterSSResp---|<-------RegisterSSResp-------|
         *  |                    |<--InsertSubscriberDataReq---|
         *  |                    |---InsertSubscriberDataResp->|
         */

        Subscriber subscriber = this.getSubscriberManager().getRandomSubscriber();
        boolean subscriberIsInA = subscriber.getCurrentMscNumber().equals(AttackSimulationOrganizer.defaultMscAddress);

        if(subscriber.isOperatorAHome()) {
            if(subscriberIsInA) {
                AttackSimulationOrganizer.mscAvlrA.getTestAttackClient().performRegisterSS(subscriber.getMsisdn());
                AttackSimulationOrganizer.hlrAvlrA.getTestAttackClient().performInsertSubscriberData();
            } else {
                AttackSimulationOrganizer.vlrBhlrA.getTestAttackClient().performRegisterSS(subscriber.getMsisdn());
                this.waitForRegisterSSResponse(AttackSimulationOrganizer.vlrBhlrA, true);
                AttackSimulationOrganizer.vlrBhlrA.getTestAttackClient().clearLastRegisterSSResponse();
                AttackSimulationOrganizer.hlrAvlrB.getTestAttackServer().performInsertSubscriberData();
            }
        } else {
            if(subscriberIsInA) {
                AttackSimulationOrganizer.vlrAhlrB.getTestAttackServer().performRegisterSS(subscriber.getMsisdn());
                this.waitForRegisterSSResponse(AttackSimulationOrganizer.vlrAhlrB, false);
                AttackSimulationOrganizer.vlrAhlrB.getTestAttackServer().clearLastRegisterSSResponse();
                AttackSimulationOrganizer.hlrBvlrA.getTestAttackClient().performInsertSubscriberData();
            }
        }
    }

    private void performErasureProcedure() {
        /**
         * EraseSS is a Category 3 message, is used between operator networks.
         *
         * Process per standard 22.3:
         * MSC                  VLR                           HLR
         *  |-----EraseSSReq---->|---------EraseSSReq--------->|
         *  |<----EraseSSResp----|<--------EraseSSResp---------|
         *  |                    |<--InsertSubscriberDataReq---|
         *  |                    |---InsertSubscriberDataResp->|
         */

        Subscriber subscriber = this.getSubscriberManager().getRandomSubscriber();
        boolean subscriberIsInA = subscriber.getCurrentMscNumber().equals(AttackSimulationOrganizer.defaultMscAddress);

        if(subscriber.isOperatorAHome()) {
            if(subscriberIsInA) {
                AttackSimulationOrganizer.mscAvlrA.getTestAttackClient().performEraseSS();
                AttackSimulationOrganizer.hlrAvlrA.getTestAttackClient().performInsertSubscriberData();
            } else {
                AttackSimulationOrganizer.vlrBhlrA.getTestAttackClient().performEraseSS();
                this.waitForRegisterSSResponse(AttackSimulationOrganizer.vlrBhlrA, true);
                AttackSimulationOrganizer.vlrBhlrA.getTestAttackClient().clearLastEraseSSResponse();
                AttackSimulationOrganizer.hlrAvlrB.getTestAttackServer().performInsertSubscriberData();
            }
        } else {
            if(subscriberIsInA) {
                AttackSimulationOrganizer.vlrAhlrB.getTestAttackServer().performEraseSS();
                this.waitForRegisterSSResponse(AttackSimulationOrganizer.vlrAhlrB, false);
                AttackSimulationOrganizer.vlrAhlrB.getTestAttackServer().clearLastEraseSSResponse();
                AttackSimulationOrganizer.hlrBvlrA.getTestAttackClient().performInsertSubscriberData();
            }
        }
    }

    private void performActivationProcedure() {
        /**
         * Process per standard 22.4:
         * MSC                  VLR                           HLR
         *  |----ActivateSSReq-->|-------ActivateSSReq-------->|
         *  |<--GetPasswordReq---|<------GetPasswordReq--------|
         *  |---GetPasswordResp->|-------GetPasswordResp------>|
         *  |<---ActivateSSResp--|<------ActivateSSResp--------|
         *  |                    |<--InsertSubscriberDataReq---|
         *  |                    |---InsertSubscriberDataResp->|
         */
    }

    private void performDeactivationProcedure() {
        /**
         * Process per standard 22.5:
         * MSC                    VLR                             HLR
         *  |----DeactivateSSReq-->|-------DeactivateSSReq-------->|
         *  |<---GetPasswordReq----|<-------GetPasswordReq---------|
         *  |----GetPasswordResp-->|--------GetPasswordResp------->|
         *  |<---DeactivateSSResp--|<------DeactivateSSResp--------|
         *  |                      |<---InsertSubscriberDataReq----|
         *  |                      |----InsertSubscriberDataResp-->|
         */
    }

    private void performInterrogationProcedure() {
        /**
         * Process per standard 22.6:
         * MSC                     VLR                           HLR
         *  |---InterrogateSSReq--->|------InterrogateSSReq------>|
         *  |<--InterrogateSSResp---|<-----InterrogateSSResp------|
         *
         *  NOTE: Message to HLR is optional.
         */
    }

    private void performPasswordRegistrationProcedure() {
        /**
         * Process per standard 22.8:
         * MSC                        VLR                             HLR
         *  |----RegisterPasswordReq-->|-----RegisterPasswordReq------>|
         *  |<-----GetPasswordReq------|<-------GetPasswordReq---------|
         *  |------GetPasswordResp---->|--------GetPasswordResp------->|
         *  |<-----GetPasswordReq------|<-------GetPasswordReq---------|
         *  |------GetPasswordResp---->|--------GetPasswordResp------->|
         *  |<-----GetPasswordReq------|<-------GetPasswordReq---------|
         *  |------GetPasswordResp---->|--------GetPasswordResp------->|
         *  |<---RegisterPasswordResp--|<----RegisterPasswordResp------|
         */
    }

    private void performProcessUnstructuredSSRequest() {
        //this.mscAvlrA.getTestAttackClient().performProcessUnstructuredSSRequest();
        //this.vlrAhlrA.getTestAttackClient().performProcessUnstructuredSSRequest();
        //this.vlrAgsmscfA.getTestAttackClient().performProcessUnstructuredSSRequest();
    }

    private void performUnstructuredSSRequest() {
        //this.hlrAvlrA.getTestAttackClient().performUnstructuredSSRequest();
        //this.gsmscfAvlrA.getTestAttackClient().performUnstructuredSSRequest();
        //this.vlrAmscA.getTestAttackClient().performUnstructuredSSRequest();
    }

    private void performUnstructuredSSNotify () {
        //this.hlrAvlrA.getTestAttackClient().performUnstructuredSSRequest();
        //this.gsmscfAvlrA.getTestAttackClient().performUnstructuredSSRequest();
        //this.vlrAmscA.getTestAttackClient().performUnstructuredSSRequest();
    }

    private void performInformServiceCentre() {
        //this.hlrAmscA.getTestAttackServer().performInformServiceCentre();
    }

    private void performSendRoutingInfoForGPRS() {
        Subscriber subscriber = this.getSubscriberManager().getRandomSubscriber();
        ISDNAddressString ggsnNumber = this.getSgsnAhlrA().getMapMan().getMAPStack().getMAPProvider()
            .getMAPParameterFactory().createISDNAddressString(
                        AddressNature.international_number,
                        NumberingPlan.ISDN,
                        AttackSimulationOrganizer.OPERATOR_A_GT);

        AttackSimulationOrganizer.sgsnAhlrA.getTestAttackClient().performSendRoutingInfoForGPRS(subscriber.getImsi(), ggsnNumber);
    }

    public void stop() {
        AttackSimulationOrganizer.mscAmscB.stop();
        AttackSimulationOrganizer.mscBmscA.stop();
        AttackSimulationOrganizer.mscAhlrA.stop();
        AttackSimulationOrganizer.hlrAmscA.stop();
        AttackSimulationOrganizer.mscAsmscA.stop();
        AttackSimulationOrganizer.smscAmscA.stop();
        AttackSimulationOrganizer.mscAvlrA.stop();
        AttackSimulationOrganizer.vlrAmscA.stop();
        AttackSimulationOrganizer.smscAhlrA.stop();
        AttackSimulationOrganizer.hlrAsmscA.stop();
        AttackSimulationOrganizer.hlrAvlrA.stop();
        AttackSimulationOrganizer.vlrAhlrA.stop();
        AttackSimulationOrganizer.sgsnAhlrA.stop();
        AttackSimulationOrganizer.hlrAsgsnA.stop();
        AttackSimulationOrganizer.gsmscfAhlrA.stop();
        AttackSimulationOrganizer.hlrAgsmscfA.stop();
        AttackSimulationOrganizer.gsmscfAvlrA.stop();
        AttackSimulationOrganizer.vlrAgsmscfA.stop();
        AttackSimulationOrganizer.attackerBmscA.stop();
        AttackSimulationOrganizer.mscAattackerB.stop();
        AttackSimulationOrganizer.attackerBhlrA.stop();
        AttackSimulationOrganizer.hlrAattackerB.stop();
        AttackSimulationOrganizer.attackerBsmscA.stop();
        AttackSimulationOrganizer.smscAattackerB.stop();
        AttackSimulationOrganizer.attackerBvlrA.stop();
        AttackSimulationOrganizer.vlrAattackerB.stop();
        AttackSimulationOrganizer.smscAsmscB.stop();
        AttackSimulationOrganizer.smscBsmscA.stop();
        AttackSimulationOrganizer.smscAhlrB.stop();
        AttackSimulationOrganizer.hlrBsmscA.stop();
        AttackSimulationOrganizer.smscBhlrA.stop();
        AttackSimulationOrganizer.hlrAsmscB.stop();
        AttackSimulationOrganizer.mscBhlrA.stop();
        AttackSimulationOrganizer.hlrAmscB.stop();
        AttackSimulationOrganizer.mscBsmscA.stop();
        AttackSimulationOrganizer.smscAmscB.stop();
        AttackSimulationOrganizer.mscBvlrA.stop();
        AttackSimulationOrganizer.vlrAmscB.stop();
        AttackSimulationOrganizer.hlrBvlrA.stop();
        AttackSimulationOrganizer.vlrAhlrB.stop();
        AttackSimulationOrganizer.vlrBvlrA.stop();
        AttackSimulationOrganizer.vlrAvlrB.stop();
        AttackSimulationOrganizer.vlrBhlrA.stop();
        AttackSimulationOrganizer.hlrAvlrB.stop();
    }

    public void execute() {
    }

    public String getState() {
        return null;
    }

    public enum SimpleAttackGoal {
        LOCATION_ATI,
        LOCATION_PSI,
        INTERCEPT_SMS,
        TEST_PORTS,
    }
}
