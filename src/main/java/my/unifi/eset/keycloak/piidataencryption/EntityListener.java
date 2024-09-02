package my.unifi.eset.keycloak.piidataencryption;

import org.hibernate.boot.Metadata;
import org.hibernate.boot.spi.BootstrapContext;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.event.service.spi.EventListenerRegistry;
import org.hibernate.event.spi.EventType;
import org.hibernate.event.spi.PreInsertEvent;
import org.hibernate.event.spi.PreInsertEventListener;
import org.hibernate.event.spi.PreLoadEvent;
import org.hibernate.event.spi.PreLoadEventListener;
import org.hibernate.event.spi.PreUpdateEvent;
import org.hibernate.event.spi.PreUpdateEventListener;
import org.hibernate.integrator.spi.Integrator;
import org.hibernate.service.spi.SessionFactoryServiceRegistry;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.jpa.entities.UserAttributeEntity;
import org.keycloak.representations.userprofile.config.UPAttribute;
import org.keycloak.userprofile.DeclarativeUserProfileProvider;
import org.keycloak.userprofile.UserProfileProvider;
import org.keycloak.utils.KeycloakSessionUtil;

/**
 * Listen to PrePersist, PreUpdate & PostLoad entity events and perform
 * encryption and decryption if entity is UserAttributeEntity
 *
 * @author MLukman (https://github.com/MLukman)
 */
public class EntityListener implements Integrator, PreLoadEventListener, PreInsertEventListener, PreUpdateEventListener {

    static final Logger logger = Logger.getLogger(EncryptionUtil.class);

    @Override
    public void integrate(Metadata metadata, BootstrapContext bootstrapContext, SessionFactoryImplementor sessionFactory) {
        EventListenerRegistry eventListenerRegistry = sessionFactory.getServiceRegistry()
                .getService(EventListenerRegistry.class);
        eventListenerRegistry.appendListeners(EventType.PRE_LOAD, this);
        eventListenerRegistry.appendListeners(EventType.PRE_UPDATE, this);
        eventListenerRegistry.appendListeners(EventType.PRE_INSERT, this);
    }

    @Override
    public void disintegrate(SessionFactoryImplementor sfi, SessionFactoryServiceRegistry sfsr) {
    }

    @Override
    public void onPreLoad(PreLoadEvent ple) {
        if (ple.getEntity() instanceof UserAttributeEntity uae) {
            String[] propertyNames = ple.getPersister().getEntityMetamodel().getPropertyNames();
            Object[] state = ple.getState();
            for (int i = 0; i < propertyNames.length; i++) {
                if ("value".equalsIgnoreCase(propertyNames[i]) && EncryptionUtil.isEncryptedValue((String) state[i])) {
                    state[i] = EncryptionUtil.decryptValue((String) state[i]);
                    if (EncryptionUtil.isEncryptedValue((String) state[i])) {
                        logger.warnf("Failed to decrypt user attribute %s", uae.getId());
                    } else {
                        logger.debugf("Successfully decrypted user attribute %s", uae.getId());
                    }
                }
            }
        }
    }

    @Override
    public boolean onPreInsert(PreInsertEvent pie) {
        if (pie.getEntity() instanceof UserAttributeEntity uae && shouldEncryptAttribute(uae)) {
            doEncryptValue(uae,
                    pie.getPersister().getEntityMetamodel().getPropertyNames(),
                    pie.getState());
        }
        return false;
    }

    @Override
    public boolean onPreUpdate(PreUpdateEvent pue) {
        if (pue.getEntity() instanceof UserAttributeEntity uae && shouldEncryptAttribute(uae)) {
            doEncryptValue(uae,
                    pue.getPersister().getEntityMetamodel().getPropertyNames(),
                    pue.getState());
        }
        return false;
    }

    void doEncryptValue(UserAttributeEntity uae, String[] propertyNames, Object[] state) {
        if (uae.getValue() == null) {
            logger.debugf("Skipped encrypting attribute %s for user %s because value is null", uae.getName(), uae.getUser().getId());
            return;
        }
        if (EncryptionUtil.isEncryptedValue(uae.getValue())) {
            // Skipped because already encrypted
            return;
        }
        String encryptedValue = EncryptionUtil.encryptValue(uae.getValue());
        if (EncryptionUtil.isEncryptedValue(encryptedValue)) {
            for (int i = 0; i < propertyNames.length; i++) {
                if ("value".equalsIgnoreCase(propertyNames[i])) {
                    state[i] = encryptedValue;
                    logger.debugf("Successfully encrypted attribute %s for user %s", uae.getName(), uae.getUser().getId());
                    return;
                }
            }
        }
        logger.warnf("Failed to encrypt attribute %s for user %s", uae.getName(), uae.getUser().getId());
    }

    boolean shouldEncryptAttribute(UserAttributeEntity userAttributeEntity) {
        if (userAttributeEntity.getName().startsWith("pii-")) {
            return true;
        }
        KeycloakSession ks = KeycloakSessionUtil.getKeycloakSession();
        UserProfileProvider upp = ks.getProvider(UserProfileProvider.class);
        if (upp instanceof DeclarativeUserProfileProvider dup) {
            UPAttribute upa = dup.getConfiguration().getAttribute(userAttributeEntity.getName());
            if (upa != null && upa.getValidations().containsKey(PiiDataEncryptionValidatorProvider.ID)) {
                return true;
            }
        }
        return false;
    }

}
