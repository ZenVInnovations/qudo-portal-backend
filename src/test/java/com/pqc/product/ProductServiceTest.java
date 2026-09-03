package com.pqc.product;

import com.pqc.product.dto.AdminProductDto;
import com.pqc.product.dto.UpdateProductRequest;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit test for the update/audit logic — no Spring, no DB, no native lib. Proves
 * that only actually-changed fields are applied and audited.
 */
class ProductServiceTest {

    private final ProductRepository products = mock(ProductRepository.class);
    private final ProductAuditRepository audit = mock(ProductAuditRepository.class);
    private final ProductService service = new ProductService(products, audit);

    private Product sample() {
        Product p = new Product();
        p.setProductKey("qudossl-community");
        p.setName("QudoSSL Community Edition");
        p.setEnabled(true);
        p.setDisplayOrder(1);
        p.setVisibility(ProductVisibility.PUBLIC);
        p.setProductType(ProductType.QUDOSSL_EDITION);
        return p;
    }

    private UpdateProductRequest req(Boolean enabled, Integer order, String visibility) {
        return new UpdateProductRequest(enabled, order, visibility, null, null, null, null, null);
    }

    @Test
    void togglingEnabledAppliesChangeAndWritesOneAuditRow() {
        Product p = sample();
        when(products.findById(1L)).thenReturn(Optional.of(p));

        AdminProductDto dto = service.updateProduct(1L, req(false, null, null), "alice");

        assertThat(p.isEnabled()).isFalse();
        assertThat(dto.enabled()).isFalse();

        ArgumentCaptor<ProductAuditEntry> captor = ArgumentCaptor.forClass(ProductAuditEntry.class);
        verify(audit, times(1)).save(captor.capture());
        ProductAuditEntry entry = captor.getValue();
        assertThat(entry.getFieldChanged()).isEqualTo("enabled");
        assertThat(entry.getOldValue()).isEqualTo("true");
        assertThat(entry.getNewValue()).isEqualTo("false");
        assertThat(entry.getAdminUsername()).isEqualTo("alice");
        assertThat(entry.getProductKey()).isEqualTo("qudossl-community");
    }

    @Test
    void unchangedValuesWriteNoAudit() {
        Product p = sample();
        when(products.findById(1L)).thenReturn(Optional.of(p));

        service.updateProduct(1L, req(true, 1, "PUBLIC"), "alice");

        verify(audit, never()).save(any());
    }

    @Test
    void multipleChangedFieldsWriteMultipleAuditRows() {
        Product p = sample();
        when(products.findById(1L)).thenReturn(Optional.of(p));

        service.updateProduct(1L, req(false, 5, "HIDDEN"), "bob");

        assertThat(p.isEnabled()).isFalse();
        assertThat(p.getDisplayOrder()).isEqualTo(5);
        assertThat(p.getVisibility()).isEqualTo(ProductVisibility.HIDDEN);
        verify(audit, times(3)).save(any());
    }

    @Test
    void unknownIdThrowsAndAuditsNothing() {
        when(products.findById(99L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.updateProduct(99L, req(false, null, null), "alice"))
                .isInstanceOf(ProductNotFoundException.class);
        verify(audit, never()).save(any());
    }
}
