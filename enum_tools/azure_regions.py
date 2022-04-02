"""
File used to track the DNS regions for Azure resources.
"""

# Some enumeration tasks will need to go through the complete list of
# possible DNS names for each region. You may want to modify this file to
# use the regions meaningful to you.
#
# Whatever is listed in the last instance of 'REGIONS' below is what the tool
# will use.


# Here is the list I get when running `az account list-locations` in Azure
# Powershell:
REGIONS = ['eastasia', 'southeastasia', 'centralus', 'eastus', 'eastus2',
           'westus', 'northcentralus', 'southcentralus', 'northeurope',
           'westeurope', 'japanwest', 'japaneast', 'brazilsouth',
           'australiaeast', 'australiasoutheast', 'southindia', 'centralindia',
           'westindia', 'canadacentral', 'canadaeast', 'uksouth', 'ukwest',
           'westcentralus', 'westus2', 'koreacentral', 'koreasouth',
           'francecentral', 'francesouth', 'australiacentral',
           'australiacentral2', 'southafricanorth', 'southafricawest']


# And here I am limiting the search by overwriting this variable:
REGIONS = ['eastus', ]
